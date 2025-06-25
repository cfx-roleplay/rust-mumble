use crate::error::DecryptError;
use crate::proto::mumble::CryptSetup;
use crate::voice::{VoicePacket, VoicePacketDst, decode_voice_packet, encode_voice_packet};
use aes::Aes128;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use bytes::BytesMut;
use ring::rand::{SecureRandom, SystemRandom};
use std::time::Instant;

lazy_static! {
    static ref SYSTEM_RANDOM: SystemRandom = SystemRandom::new();
}

const KEY_SIZE: usize = 16;
const BLOCK_SIZE: usize = std::mem::size_of::<u128>();

pub struct CryptState {
    pub key: [u8; KEY_SIZE],
    // internally as native endianness, externally as little endian and during ocb_* as big endian
    encrypt_nonce: u128,
    decrypt_nonce: u128,
    decrypt_history: [u8; 0x100],
    aes: Aes128,

    pub good: u32,
    pub late: u32,
    pub lost: u32,
    pub resync: u32,
    pub last_good: Instant,

    // Remote -> client
    pub remote_late: u32,
    pub remote_good: u32,
    pub remote_lost: u32,
    pub remote_resync: u32,
    
    // Reset tracking for exponential backoff
    pub reset_attempts: u32,
    pub last_reset: Instant,
}

impl Default for CryptState {
    fn default() -> Self {
        let mut key = [0u8; KEY_SIZE];
        SYSTEM_RANDOM.fill(&mut key).expect("Failed to generate random key");

        Self {
            aes: Aes128::new(GenericArray::from_slice(&key)),
            key,
            encrypt_nonce: 0,
            decrypt_nonce: 1 << 127,
            decrypt_history: [0; 0x100],

            good: 0,
            late: 0,
            lost: 0,
            resync: 0,
            last_good: Instant::now(),

            remote_late: 0,
            remote_good: 0,
            remote_lost: 0,
            remote_resync: 0,
            
            // Reset tracking for exponential backoff
            reset_attempts: 0,
            last_reset: Instant::now(),
        }
    }
}

impl CryptState {
    pub fn reset(&mut self) {
        tracing::info!("Resetting crypt state - good: {}, late: {}, lost: {}, resync: {}", 
                      self.good, self.late, self.lost, self.resync);
        
        // Track crypt reset metric
        crate::metrics::CRYPT_RESETS_TOTAL.inc();
        
        self.encrypt_nonce = 0;
        self.decrypt_nonce = 1 << 127;
        self.decrypt_history = [0; 0x100];
        self.good = 0;
        self.late = 0;
        self.lost = 0;
        self.resync = 0;
        self.last_good = Instant::now();
        
        // Also reset remote stats to ensure clean slate
        self.remote_late = 0;
        self.remote_good = 0;
        self.remote_lost = 0;
        self.remote_resync = 0;
        
        // Update reset tracking
        self.reset_attempts += 1;
        self.last_reset = Instant::now();
    }

    /// Check if a reset should be allowed based on exponential backoff
    pub fn should_allow_reset(&self) -> bool {
        let now = Instant::now();
        let time_since_last_reset = now.duration_since(self.last_reset);
        
        // Exponential backoff: 1s, 2s, 4s, 8s, max 30s
        let min_interval = std::cmp::min(1000 * (1 << self.reset_attempts), 30000);
        
        time_since_last_reset.as_millis() > min_interval as u128
    }
    
    /// Reset the reset attempt counter on successful operation
    pub fn reset_attempt_counter(&mut self) {
        if self.reset_attempts > 0 {
            tracing::info!("Resetting attempt counter after successful operation");
            self.reset_attempts = 0;
        }
    }

    /// Returns the nonce used for encrypting.
    pub fn get_encrypt_nonce(&self) -> [u8; BLOCK_SIZE] {
        self.encrypt_nonce.to_le_bytes()
    }

    /// Returns the nonce used for decrypting.
    pub fn get_decrypt_nonce(&self) -> [u8; BLOCK_SIZE] {
        self.decrypt_nonce.to_le_bytes()
    }

    pub fn set_decrypt_nonce(&mut self, nonce: &[u8]) {
        let old_nonce = self.decrypt_nonce;
        self.decrypt_nonce = u128::from_le_bytes(nonce.try_into().unwrap());
        self.resync += 1;
        
        // Clear history buffer on resync to prevent false positives
        self.decrypt_history = [0; 0x100];
        
        tracing::info!("Crypt resync: old nonce: {}, new nonce: {}, resync count: {}", 
                      old_nonce, self.decrypt_nonce, self.resync);
    }

    pub fn get_crypt_setup(&self) -> CryptSetup {
        let mut crypt_setup = CryptSetup::new();

        crypt_setup.set_key(self.key.to_vec());
        crypt_setup.set_client_nonce(self.get_decrypt_nonce().to_vec());
        crypt_setup.set_server_nonce(self.get_encrypt_nonce().to_vec());

        crypt_setup
    }

    /// Encrypts an encoded voice packet and returns the resulting bytes.
    pub fn encrypt<EncodeDst: VoicePacketDst>(&mut self, packet: &VoicePacket<EncodeDst>, dst: &mut BytesMut) {
        self.encrypt_nonce = self.encrypt_nonce.wrapping_add(1);

        // Leave four bytes for header
        dst.resize(4, 0);
        let mut inner = dst.split_off(4);

        encode_voice_packet(packet, &mut inner);

        let tag = self.ocb_encrypt(inner.as_mut());
        dst.unsplit(inner);

        dst[0] = self.encrypt_nonce as u8;
        dst[1..4].copy_from_slice(&tag.to_be_bytes()[0..3]);
    }

    /// Decrypts a voice packet and (if successful) returns the `Result` of parsing the packet.
    pub fn decrypt<DecodeDst: VoicePacketDst>(&mut self, buf: &mut BytesMut) -> Result<VoicePacket<DecodeDst>, DecryptError> {
        if buf.len() < 4 {
            return Err(DecryptError::Eof);
        }
        let header = buf.split_to(4);
        let nonce_0 = header[0];

        // If we update our decrypt_nonce and the tag check fails or we've been processing late
        // packets, we need to revert it
        let saved_nonce = self.decrypt_nonce;
        let mut late = false; // will always restore nonce if this is the case
        let mut lost = 0; // for stats only

        // Use 16 bits for better nonce comparison instead of just 8 bits
        let expected_nonce_low16 = (self.decrypt_nonce.wrapping_add(1) & 0xFFFF) as u16;
        let received_nonce_low16 = (nonce_0 as u16) | ((self.decrypt_nonce & 0xFF00) as u16);
        
        // Check if this is the expected next packet using 16-bit comparison
        if (self.decrypt_nonce.wrapping_add(1) as u8) == nonce_0 {
            // Normal in-order packet
            self.decrypt_nonce = self.decrypt_nonce.wrapping_add(1);
        } else {
            // Handle out-of-order, late, or wrapped packets
            let nonce_diff = nonce_0.wrapping_sub(self.decrypt_nonce as u8) as i8;
            
            // Handle nonce wrap-around more carefully
            let mut adjusted_diff = nonce_diff;
            if nonce_diff > 127 {
                // Likely a wrap-around in the negative direction
                adjusted_diff = nonce_diff - 256;
            } else if nonce_diff < -127 {
                // Likely a wrap-around in the positive direction  
                adjusted_diff = nonce_diff + 256;
            }
            
            self.decrypt_nonce = self.decrypt_nonce.wrapping_add(adjusted_diff as u128);

            if adjusted_diff > 0 {
                lost = i32::from(adjusted_diff - 1); // lost packets between this and the last one
                tracing::debug!("Lost {} packets, nonce diff: {}", lost, adjusted_diff);
                
                // Track lost packets metric
                crate::metrics::LOST_PACKETS_TOTAL.inc_by(lost as u64);
                
                // Track nonce wraps when we jump significantly
                if adjusted_diff > 100 {
                    crate::metrics::NONCE_WRAPS_TOTAL.inc();
                }
            } else if adjusted_diff > -30 {
                // Check for repeat packets using better history tracking
                let history_index = nonce_0 as usize;
                let expected_history = (self.decrypt_nonce >> 8) as u8;
                
                if self.decrypt_history[history_index] == expected_history {
                    self.decrypt_nonce = saved_nonce;
                    tracing::debug!("Repeat packet detected, nonce: {}, history: {}", nonce_0, expected_history);
                    
                    // Track repeat error metric
                    crate::metrics::CRYPT_ERRORS_TOTAL.with_label_values(&["repeat"]).inc();
                    
                    return Err(DecryptError::Repeat);
                }
                // just late
                late = true;
                lost = -1;
                tracing::debug!("Late packet, nonce diff: {}", adjusted_diff);
                
                // Track late packets metric
                crate::metrics::LATE_PACKETS_TOTAL.inc();
            } else {
                // Too late (more than 30 packets behind)
                self.decrypt_nonce = saved_nonce;
                tracing::warn!("Packet too late, nonce diff: {}, dropping", adjusted_diff);
                
                // Track late error metric
                crate::metrics::CRYPT_ERRORS_TOTAL.with_label_values(&["too_late"]).inc();
                
                return Err(DecryptError::Late);
            }
        }

        let tag = self.ocb_decrypt(buf.as_mut());

        if Ok(()) != ring::constant_time::verify_slices_are_equal(&header[1..4], &tag.to_be_bytes()[0..3]) {
            self.decrypt_nonce = saved_nonce;
            tracing::warn!("MAC verification failed, nonce: {}, decrypt_nonce: {}", nonce_0, self.decrypt_nonce);
            
            // Track MAC error metric
            crate::metrics::CRYPT_ERRORS_TOTAL.with_label_values(&["mac"]).inc();
            
            return Err(DecryptError::Mac);
        }

        self.decrypt_history[nonce_0 as usize] = (self.decrypt_nonce >> 8) as u8;
        self.good += 1;
        self.last_good = Instant::now();
        
        // Reset attempt counter on successful decryption
        self.reset_attempt_counter();

        if late {
            self.late += 1;
            self.decrypt_nonce = saved_nonce;
        }

        self.lost = (self.lost as i32 + lost) as u32;

        decode_voice_packet(buf)
    }

    /// Encrypt the provided buffer using AES-OCB, returning the tag.
    fn ocb_encrypt(&self, mut buf: &mut [u8]) -> u128 {
        let mut offset = self.aes_encrypt(self.encrypt_nonce.to_be());
        let mut checksum = 0u128;

        while buf.len() > BLOCK_SIZE {
            let (chunk, remainder) = buf.split_at_mut(BLOCK_SIZE);
            buf = remainder;
            let chunk: &mut [u8; BLOCK_SIZE] = chunk.try_into().expect("split_at works");

            offset = s2(offset);

            let plain = u128::from_be_bytes(*chunk);
            let encrypted = self.aes_encrypt(offset ^ plain) ^ offset;
            chunk.copy_from_slice(&encrypted.to_be_bytes());

            checksum ^= plain;
        }

        offset = s2(offset);

        let len = buf.len();
        assert!(len <= BLOCK_SIZE);
        let pad = self.aes_encrypt((len * 8) as u128 ^ offset);
        let mut block = pad.to_be_bytes();
        block[..len].copy_from_slice(buf);
        let plain = u128::from_be_bytes(block);
        let encrypted = pad ^ plain;
        buf.copy_from_slice(&encrypted.to_be_bytes()[..len]);

        checksum ^= plain;

        self.aes_encrypt(offset ^ s2(offset) ^ checksum)
    }

    /// Decrypt the provided buffer using AES-OCB, returning the tag.
    /// **Make sure to verify that the tag matches!**
    fn ocb_decrypt(&self, mut buf: &mut [u8]) -> u128 {
        let mut offset = self.aes_encrypt(self.decrypt_nonce.to_be());
        let mut checksum = 0u128;

        while buf.len() > BLOCK_SIZE {
            let (chunk, remainder) = buf.split_at_mut(BLOCK_SIZE);
            buf = remainder;
            let chunk: &mut [u8; BLOCK_SIZE] = chunk.try_into().expect("split_at works");

            offset = s2(offset);

            let encrypted = u128::from_be_bytes(*chunk);
            let plain = self.aes_decrypt(offset ^ encrypted) ^ offset;
            chunk.copy_from_slice(&plain.to_be_bytes());

            checksum ^= plain;
        }

        offset = s2(offset);

        let len = buf.len();
        assert!(len <= BLOCK_SIZE);
        let pad = self.aes_encrypt((len * 8) as u128 ^ offset);
        let mut block = [0; BLOCK_SIZE];
        block[..len].copy_from_slice(buf);
        let plain = u128::from_be_bytes(block) ^ pad;
        buf.copy_from_slice(&plain.to_be_bytes()[..len]);

        checksum ^= plain;

        self.aes_encrypt(offset ^ s2(offset) ^ checksum)
    }

    /// AES-128 encryption primitive.
    fn aes_encrypt(&self, data: u128) -> u128 {
        let mut data_bytes = data.to_be_bytes();
        let block = GenericArray::from_mut_slice(&mut data_bytes);
        self.aes.encrypt_block(block);

        u128::from_be_bytes(data_bytes)
    }

    /// AES-128 decryption primitive.
    fn aes_decrypt(&self, data: u128) -> u128 {
        let mut data_bytes = data.to_be_bytes();
        let block = GenericArray::from_mut_slice(&mut data_bytes);
        self.aes.decrypt_block(block);

        u128::from_be_bytes(data_bytes)
    }
}

#[inline]
fn s2(block: u128) -> u128 {
    let rot = block.rotate_left(1);
    let carry = rot & 1;
    rot ^ (carry * 0x86)
}
