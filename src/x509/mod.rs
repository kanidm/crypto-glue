
use x509_cert::serial_number::SerialNumber;

pub mod display;

pub fn uuid_to_serial(serial_uuid: uuid::Uuid) -> SerialNumber {
    let mut serial_bytes: [u8; 17] = [0; 17];
    serial_bytes[0] = 0x01;
    let update_bytes = &mut serial_bytes[1..];
    update_bytes.copy_from_slice(serial_uuid.as_bytes());

    SerialNumber::new(&serial_bytes).unwrap()
}
