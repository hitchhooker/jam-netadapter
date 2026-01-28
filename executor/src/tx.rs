//! cosmos tx building with proper protobuf encoding
//!
//! uses ibc-proto for MsgRecvPacket, MsgAcknowledgement, MsgTimeout

use ibc_proto::ibc::core::channel::v1::{
    MsgRecvPacket, MsgAcknowledgement, MsgTimeout,
    Packet as ProtoPacket,
};
use ibc_proto::ibc::core::client::v1::Height as ProtoHeight;
use prost::Message;

use crate::types::{Height, Packet, RelayTask};

/// build MsgRecvPacket for cosmos
pub fn build_recv_packet_msg(
    task: &RelayTask,
    signer: &str,
) -> Vec<u8> {
    let msg = MsgRecvPacket {
        packet: Some(packet_to_proto(&task.packet)),
        proof_commitment: task.proof.clone(),
        proof_height: Some(height_to_proto(&task.proof_height)),
        signer: signer.to_string(),
    };

    msg.encode_to_vec()
}

/// build MsgAcknowledgement for cosmos
pub fn build_ack_packet_msg(
    task: &RelayTask,
    acknowledgement: &[u8],
    signer: &str,
) -> Vec<u8> {
    let msg = MsgAcknowledgement {
        packet: Some(packet_to_proto(&task.packet)),
        acknowledgement: acknowledgement.to_vec(),
        proof_acked: task.proof.clone(),
        proof_height: Some(height_to_proto(&task.proof_height)),
        signer: signer.to_string(),
    };

    msg.encode_to_vec()
}

/// build MsgTimeout for cosmos
pub fn build_timeout_packet_msg(
    task: &RelayTask,
    next_sequence_recv: u64,
    signer: &str,
) -> Vec<u8> {
    let msg = MsgTimeout {
        packet: Some(packet_to_proto(&task.packet)),
        proof_unreceived: task.proof.clone(),
        proof_height: Some(height_to_proto(&task.proof_height)),
        next_sequence_recv,
        signer: signer.to_string(),
    };

    msg.encode_to_vec()
}

/// convert internal packet to protobuf
fn packet_to_proto(packet: &Packet) -> ProtoPacket {
    ProtoPacket {
        sequence: packet.sequence,
        source_port: packet.source_port.clone(),
        source_channel: packet.source_channel.clone(),
        destination_port: packet.destination_port.clone(),
        destination_channel: packet.destination_channel.clone(),
        data: packet.data.clone(),
        timeout_height: Some(height_to_proto(&packet.timeout_height)),
        timeout_timestamp: packet.timeout_timestamp,
    }
}

/// convert internal height to protobuf
fn height_to_proto(height: &Height) -> ProtoHeight {
    ProtoHeight {
        revision_number: height.revision_number,
        revision_height: height.revision_height,
    }
}

/// wrap message in cosmos tx body
pub fn wrap_in_tx_body(type_url: &str, msg_bytes: &[u8]) -> Vec<u8> {
    use ibc_proto::google::protobuf::Any;
    use ibc_proto::cosmos::tx::v1beta1::{TxBody, TxRaw, AuthInfo, SignerInfo, ModeInfo, Fee};
    use ibc_proto::cosmos::tx::v1beta1::mode_info::Single;

    let msg_any = Any {
        type_url: type_url.to_string(),
        value: msg_bytes.to_vec(),
    };

    let tx_body = TxBody {
        messages: vec![msg_any],
        memo: String::new(),
        timeout_height: 0,
        extension_options: vec![],
        non_critical_extension_options: vec![],
    };

    // placeholder auth info - real impl needs proper signing
    let auth_info = AuthInfo {
        signer_infos: vec![SignerInfo {
            public_key: None,
            mode_info: Some(ModeInfo {
                sum: Some(ibc_proto::cosmos::tx::v1beta1::mode_info::Sum::Single(
                    Single { mode: 1 } // SIGN_MODE_DIRECT
                )),
            }),
            sequence: 0,
        }],
        fee: Some(Fee {
            amount: vec![],
            gas_limit: 200000,
            payer: String::new(),
            granter: String::new(),
        }),
        tip: None,
    };

    let tx_raw = TxRaw {
        body_bytes: tx_body.encode_to_vec(),
        auth_info_bytes: auth_info.encode_to_vec(),
        signatures: vec![vec![]], // placeholder - needs real signature
    };

    tx_raw.encode_to_vec()
}

/// type urls for ibc messages
pub mod type_urls {
    pub const MSG_RECV_PACKET: &str = "/ibc.core.channel.v1.MsgRecvPacket";
    pub const MSG_ACKNOWLEDGEMENT: &str = "/ibc.core.channel.v1.MsgAcknowledgement";
    pub const MSG_TIMEOUT: &str = "/ibc.core.channel.v1.MsgTimeout";
}
