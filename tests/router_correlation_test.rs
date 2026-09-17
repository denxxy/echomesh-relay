use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use bytes::Bytes;

use echomesh_relay::client::handlers::ClientEventHandler;
use echomesh_relay::client::routing::ClientInboundRouter;
use echomesh_relay::protocol::envelope::{MessageEnvelope, MessageType};
use echomesh_relay::protocol::messages::{DeliveryStatus, ServerToClientMessage};

struct TestEventHandler {
    events_received: AtomicUsize,
    last_delivery_status: Arc<Mutex<Option<DeliveryStatus>>>,
}

impl ClientEventHandler for TestEventHandler {
    fn on_delivery_status(&self, _message_id: u64, status: DeliveryStatus) {
        self.events_received.fetch_add(1, Ordering::SeqCst);
        *self.last_delivery_status.lock().unwrap() = Some(status);
    }
}

#[tokio::test]
async fn test_request_response_out_of_order_correlation() {
    let router = ClientInboundRouter::new();

    // Register 3 pending requests with IDs 101, 102, 103
    let rx101 = router.register_pending(101).await;
    let rx102 = router.register_pending(102).await;
    let rx103 = router.register_pending(103).await;

    // Simulate responses arriving OUT OF ORDER: 103, 101, 102
    let resp103 = ServerToClientMessage::SendMessageResponse {
        message_id: 103,
        accepted: true,
    };
    let env103 = MessageEnvelope::new(MessageType::SendMessageResponse, 993, 103, 0, Bytes::new()).unwrap();
    router.dispatch(&env103, resp103.clone()).await.unwrap();

    let resp101 = ServerToClientMessage::SendMessageResponse {
        message_id: 101,
        accepted: true,
    };
    let env101 = MessageEnvelope::new(MessageType::SendMessageResponse, 991, 101, 0, Bytes::new()).unwrap();
    router.dispatch(&env101, resp101.clone()).await.unwrap();

    let resp102 = ServerToClientMessage::SendMessageResponse {
        message_id: 102,
        accepted: false,
    };
    let env102 = MessageEnvelope::new(MessageType::SendMessageResponse, 992, 102, 0, Bytes::new()).unwrap();
    router.dispatch(&env102, resp102.clone()).await.unwrap();

    // Verify all 3 futures resolve to their exact corresponding response
    let res101 = rx101.await.unwrap();
    let res102 = rx102.await.unwrap();
    let res103 = rx103.await.unwrap();

    assert_eq!(res101, resp101);
    assert_eq!(res102, resp102);
    assert_eq!(res103, resp103);
}

#[tokio::test]
async fn test_server_event_push_to_handler() {
    let router = ClientInboundRouter::new();

    let handler = Arc::new(TestEventHandler {
        events_received: AtomicUsize::new(0),
        last_delivery_status: Arc::new(Mutex::new(None)),
    });

    router.add_event_handler(handler.clone()).await;

    // Send an unsolicited DeliveryStatusEvent
    let event = ServerToClientMessage::DeliveryStatusEvent {
        message_id: 888,
        status: DeliveryStatus::Delivered,
    };
    let env = MessageEnvelope::new(MessageType::DeliveryStatusEvent, 555, 0, 0, Bytes::new()).unwrap();

    router.dispatch(&env, event).await.unwrap();

    assert_eq!(handler.events_received.load(Ordering::SeqCst), 1);
    assert_eq!(*handler.last_delivery_status.lock().unwrap(), Some(DeliveryStatus::Delivered));
}
