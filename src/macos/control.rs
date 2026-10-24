//! Own one connection independently of any individual CLI request.
use super::{Response, connection::ConnectionManager, credentials::Credentials, service::Status};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::{Mutex, mpsc, oneshot};

type Reply = oneshot::Sender<Response>;
enum Message {
    Connect(Option<Credentials>, Reply),
    Disconnect(Reply),
    Shutdown(Reply),
}

#[derive(Clone)]
pub struct ConnectionControl {
    sender: mpsc::Sender<Message>,
    closing: Arc<AtomicBool>,
}

impl ConnectionControl {
    pub async fn new(mut manager: ConnectionManager, status: Arc<Mutex<Status>>) -> Self {
        if let Err(error) = manager.recover().await {
            let mut snapshot = status.lock().await;
            snapshot.connection = "failed".into();
            snapshot.last_error = Some(error.to_string());
        }
        let (sender, receiver) = mpsc::channel(32);
        tokio::spawn(worker(manager, receiver, status));
        Self {
            sender,
            closing: Arc::new(AtomicBool::new(false)),
        }
    }
    pub async fn connect(&self, credentials: Option<Credentials>) -> Response {
        if self.closing.load(Ordering::Acquire) {
            return Response::error("service_stopping", "VPN service is stopping");
        }
        let (reply, receive) = oneshot::channel();
        self.call(Message::Connect(credentials, reply), receive)
            .await
    }
    pub async fn disconnect(&self) -> Response {
        let (reply, receive) = oneshot::channel();
        self.call(Message::Disconnect(reply), receive).await
    }
    pub async fn shutdown(&self) -> Response {
        self.closing.store(true, Ordering::Release);
        let (reply, receive) = oneshot::channel();
        self.call(Message::Shutdown(reply), receive).await
    }
    async fn call(&self, message: Message, receive: oneshot::Receiver<Response>) -> Response {
        match tokio::time::timeout(Duration::from_secs(2), self.sender.send(message)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return Response::error(
                    "service_unavailable",
                    "VPN connection controller is unavailable",
                );
            }
            Err(_) => {
                return Response::error(
                    "operation_in_progress",
                    "VPN connection controller is busy",
                );
            }
        }
        match tokio::time::timeout(Duration::from_secs(95), receive).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) => {
                Response::error("service_unavailable", "VPN connection controller stopped")
            }
            Err(_) => Response::error(
                "operation_timeout",
                "VPN operation deadline exceeded; query status before retrying",
            ),
        }
    }
}

fn reply_all(replies: Vec<Reply>, response: &Response) {
    for reply in replies {
        let _ = reply.send(response.clone());
    }
}

async fn worker(
    mut manager: ConnectionManager,
    mut receiver: mpsc::Receiver<Message>,
    status: Arc<Mutex<Status>>,
) {
    let mut tick = tokio::time::interval(Duration::from_millis(50));
    loop {
        let message = tokio::select! {message=receiver.recv()=>Some(message),_ = tick.tick()=>None};
        if let Some(error) = manager.forwarding_error().await
            && cleanup(
                &mut manager,
                &mut receiver,
                &status,
                Some(error),
                Vec::new(),
                Vec::new(),
                false,
            )
            .await
            .0
        {
            break;
        }
        match message {
            Some(Some(Message::Connect(credentials, reply))) => {
                if status.lock().await.connection == "connected" {
                    let _ = reply.send(Response::success(status.lock().await.clone()));
                } else if let Some(credentials) = credentials {
                    if start(&mut manager, &mut receiver, &status, credentials, reply).await {
                        break;
                    }
                } else {
                    let _ = reply.send(Response::error(
                        "credentials_required",
                        "Provide campus credentials before connecting",
                    ));
                }
            }
            Some(Some(Message::Disconnect(reply))) => {
                if cleanup(
                    &mut manager,
                    &mut receiver,
                    &status,
                    None,
                    vec![reply],
                    Vec::new(),
                    false,
                )
                .await
                .0
                {
                    break;
                }
            }
            Some(Some(Message::Shutdown(reply))) => {
                cleanup(
                    &mut manager,
                    &mut receiver,
                    &status,
                    None,
                    Vec::new(),
                    vec![reply],
                    true,
                )
                .await;
                break;
            }
            Some(None) => {
                cleanup(
                    &mut manager,
                    &mut receiver,
                    &status,
                    None,
                    Vec::new(),
                    Vec::new(),
                    true,
                )
                .await;
                break;
            }
            None => {}
        }
    }
}

enum StartResult {
    Finished(anyhow::Result<super::connection::ConnectionInfo>),
    Cancelled,
    TimedOut,
}

async fn start(
    manager: &mut ConnectionManager,
    receiver: &mut mpsc::Receiver<Message>,
    status: &Arc<Mutex<Status>>,
    credentials: Credentials,
    first_reply: Reply,
) -> bool {
    {
        let mut snapshot = status.lock().await;
        snapshot.connection = "connecting".into();
        snapshot.connection_info = None;
        snapshot.generation += 1;
    }
    let mut connects = vec![first_reply];
    let mut disconnects = Vec::new();
    let mut shutdowns = Vec::new();
    let mut shutting_down = false;
    let duration = manager.startup_timeout();
    let result = {
        let startup = manager.connect(credentials);
        tokio::pin!(startup);
        let deadline = tokio::time::sleep(duration);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                result=&mut startup=>break StartResult::Finished(result),
                _=&mut deadline=>break StartResult::TimedOut,
                message=receiver.recv()=>match message {
                    Some(Message::Connect(_,reply))=>connects.push(reply),
                    Some(Message::Disconnect(reply))=>{disconnects.push(reply);break StartResult::Cancelled;},
                    Some(Message::Shutdown(reply))=>{shutdowns.push(reply);shutting_down=true;break StartResult::Cancelled;},
                    None=>{shutting_down=true;break StartResult::Cancelled;},
                }
            }
        }
    }; // Drop the startup future before trying to clean its owned resources.
    match result {
        StartResult::Finished(Ok(info)) => {
            let mut snapshot = status.lock().await;
            snapshot.connection = "connected".into();
            snapshot.connection_info = Some(info);
            snapshot.last_error = None;
            reply_all(connects, &Response::success(snapshot.clone()));
            false
        }
        failure => {
            let (code, message) = match failure {
                StartResult::Cancelled => (
                    "connection_cancelled",
                    "VPN connection was cancelled".into(),
                ),
                StartResult::TimedOut => (
                    "connection_timeout",
                    "VPN connection startup timed out".into(),
                ),
                StartResult::Finished(Err(error)) => ("connection_failed", error.to_string()),
                StartResult::Finished(Ok(_)) => unreachable!(),
            };
            let cause = if code == "connection_cancelled" {
                None
            } else {
                Some(message.clone())
            };
            let (shutdown, cleaned) = cleanup(
                manager,
                receiver,
                status,
                cause,
                disconnects,
                shutdowns,
                shutting_down,
            )
            .await;
            let mut response = Response::error(code, message);
            if !cleaned.ok {
                response.message = format!("{}; {}", response.message, cleaned.message);
            }
            reply_all(connects, &response);
            shutdown
        }
    }
}

async fn cleanup(
    manager: &mut ConnectionManager,
    receiver: &mut mpsc::Receiver<Message>,
    status: &Arc<Mutex<Status>>,
    cause: Option<String>,
    mut disconnects: Vec<Reply>,
    mut shutdowns: Vec<Reply>,
    mut shutting_down: bool,
) -> (bool, Response) {
    status.lock().await.connection = "disconnecting".into();
    let mut closed = false;
    let result = {
        let stopping = manager.disconnect();
        tokio::pin!(stopping);
        let deadline = tokio::time::sleep(Duration::from_secs(30));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                result=&mut stopping=>break result,
                _=&mut deadline=>break Err(anyhow::anyhow!("VPN cleanup timed out; retry disconnect to finish owned-resource cleanup")),
                message=receiver.recv(),if !closed=>match message {
                    Some(Message::Connect(_,reply))=>{let _=reply.send(Response::error("operation_in_progress","VPN is disconnecting; retry connect after cleanup"));},
                    Some(Message::Disconnect(reply))=>disconnects.push(reply),
                    Some(Message::Shutdown(reply))=>{shutdowns.push(reply);shutting_down=true;},
                    None=>{closed=true;shutting_down=true;},
                }
            }
        }
    };
    let response = {
        let mut snapshot = status.lock().await;
        snapshot.connection_info = None;
        match result {
            Ok(()) => {
                snapshot.connection = if cause.is_some() && disconnects.is_empty() {
                    "failed"
                } else {
                    "disconnected"
                }
                .into();
                if let Some(cause) = cause {
                    snapshot.last_error = Some(cause);
                }
                Response::success(snapshot.clone())
            }
            Err(error) => {
                snapshot.connection = "failed".into();
                let message = match cause {
                    Some(cause) => format!("{cause}; {error}"),
                    None => error.to_string(),
                };
                snapshot.last_error = Some(message.clone());
                Response::error("cleanup_failed", message)
            }
        }
    };
    reply_all(disconnects, &response);
    reply_all(shutdowns, &response);
    (shutting_down, response)
}
