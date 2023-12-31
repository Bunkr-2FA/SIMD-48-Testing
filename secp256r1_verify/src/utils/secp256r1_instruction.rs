use {
    bytemuck::{Zeroable, Pod},
    thiserror::Error,
    p256::{
        ecdsa::{Signature, signature::Verifier},
        elliptic_curve::IsHigh
    }
};


#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum PrecompileError {
    #[error("public key is not valid")]
    InvalidPublicKey,
    #[error("signature is not valid")]
    InvalidSignature,
    #[error("offset not valid")]
    InvalidDataOffsets,
    #[error("instruction is incorrect size")]
    InvalidInstructionDataSize,
}

pub const COMPRESSED_PUBKEY_SERIALIZED_SIZE: usize = 33;
pub const SIGNATURE_SERIALIZED_SIZE: usize = 64;
pub const SIGNATURE_OFFSETS_SERIALIZED_SIZE: usize = 14;
// bytemuck requires structures to be aligned
pub const SIGNATURE_OFFSETS_START: usize = 2;
pub const DATA_START: usize = SIGNATURE_OFFSETS_SERIALIZED_SIZE + SIGNATURE_OFFSETS_START;

#[derive(Default, Debug, Copy, Clone, Zeroable,Pod, Eq, PartialEq)]
#[repr(C)]
pub struct Secp256r1SignatureOffsets {
    pub signature_offset: u16,             // offset to compact secp256r1 signature of 64 bytes
    pub signature_instruction_index: u16,  // instruction index to find signature
    pub public_key_offset: u16,            // offset to compressed public key of 33 bytes
    pub public_key_instruction_index: u16, // instruction index to find public key
    pub message_data_offset: u16,          // offset to start of message data
    pub message_data_size: u16,            // size of message data
    pub message_instruction_index: u16,    // index of instruction data to get message data
}


pub fn verify(
    data: &[u8],
    instruction_datas: &[&[u8]]
) -> Result<(), PrecompileError> {
    if data.len() < SIGNATURE_OFFSETS_START {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let num_signatures = data[0] as usize;
    if num_signatures == 0 && data.len() > SIGNATURE_OFFSETS_START {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    let expected_data_size = num_signatures
        .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
        .saturating_add(SIGNATURE_OFFSETS_START);
    // We do not check or use the byte at data[1]
    if data.len() < expected_data_size {
        return Err(PrecompileError::InvalidInstructionDataSize);
    }
    for i in 0..num_signatures {
        let start = i
            .saturating_mul(SIGNATURE_OFFSETS_SERIALIZED_SIZE)
            .saturating_add(SIGNATURE_OFFSETS_START);
        let end = start.saturating_add(SIGNATURE_OFFSETS_SERIALIZED_SIZE);

        // bytemuck wants structures aligned
        let offsets: &Secp256r1SignatureOffsets = bytemuck::try_from_bytes(&data[start..end])
            .map_err(|_| PrecompileError::InvalidDataOffsets)?;

        // Parse out signature
        let signature = get_data_slice(
            data,
            instruction_datas,
            offsets.signature_instruction_index,
            offsets.signature_offset,
            SIGNATURE_SERIALIZED_SIZE,
        )?;

        // Parse out pubkey
        let pubkey = get_data_slice(
            data,
            instruction_datas,
            offsets.public_key_instruction_index,
            offsets.public_key_offset,
            COMPRESSED_PUBKEY_SERIALIZED_SIZE
        )?;

        // Parse out message
        let message = get_data_slice(
            data,
            instruction_datas,
            offsets.message_instruction_index,
            offsets.message_data_offset,
            offsets.message_data_size as usize,
        )?;

        let signature =
        Signature::try_from(signature).map_err(|_| PrecompileError::InvalidSignature)?;

        // Enforce Low-S
        if signature.s().is_high().into() {
            return Err(PrecompileError::InvalidSignature);
        }

        let publickey = p256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey)
            .map_err(|_| PrecompileError::InvalidPublicKey)?;

        publickey.verify(&message, &signature)
            .map_err(|_| PrecompileError::InvalidSignature)?;
    }
    Ok(())
}

fn get_data_slice<'a>(
    data: &'a [u8],
    instruction_datas: &'a [&[u8]],
    instruction_index: u16,
    offset_start: u16,
    size: usize,
) -> Result<&'a [u8], PrecompileError> {
    let instruction = if instruction_index == u16::MAX {
        data
    } else {
        let signature_index = instruction_index as usize;
        if signature_index >= instruction_datas.len() {
            return Err(PrecompileError::InvalidDataOffsets);
        }
        instruction_datas[signature_index]
    };

    let start = offset_start as usize;
    let end = start.saturating_add(size);
    if end > instruction.len() {
        return Err(PrecompileError::InvalidDataOffsets);
    }

    Ok(&instruction[start..end])
}

