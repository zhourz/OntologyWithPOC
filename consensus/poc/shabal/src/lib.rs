//! An implementation of the [Shabal][1] cryptographic hash algorithm.
//!
//! There are 5 standard algorithms specified in the Shabal standard:
//!
//! * `Shabal192`, which is the `Shabal` algorithm with the result truncated to 192 bits
//! * `Shabal224`, which is the `Shabal` algorithm with the result truncated to 224 bits
//! * `Shabal256`, which is the `Shabal` algorithm with the result truncated to 256 bits.
//! * `Shabal384`, which is the `Shabal` algorithm with the result truncated to 384 bits.
//! * `Shabal512`, which is the `Shabal` algorithm with the result not truncated.
//!
//! There is a single Shabal algorithm. All variants have different intialisation and apart
//! Shabal512 truncate the result.
//!
//! # Usage
//!
//! ```rust
//! # #[macro_use] extern crate hex_literal;
//! # extern crate shabal;
//! # fn main() {
//! use shabal::{Shabal256, Digest};
//!
//! // create a Shabal256 hasher instance
//! let mut hasher = Shabal256::new();
//!
//! // process input message
//! hasher.input(b"helloworld");
//!
//! // acquire hash digest in the form of GenericArray,
//! // which in this case is equivalent to [u8; 32]
//! let result = hasher.result();
//! assert_eq!(result[..], hex!("d945dee21ffca23ac232763aa9cac6c15805f144db9d6c97395437e01c8595a8"));
//! # }
//! ```
//!
//! Also see [RustCrypto/hashes][2] readme.
//!
//! [1]: https://www.cs.rit.edu/~ark/20090927/Round2Candidates/Shabal.pdf
//! [2]: https://github.com/RustCrypto/hashes


//#![no_std]
//#![doc(html_logo_url = "https://raw.githubusercontent.com/RustCrypto/meta/master/logo_small.png")]

extern crate block_buffer;
//#[macro_use]
extern crate opaque_debug;
//#[macro_use]
pub extern crate digest;
//#[cfg(feature = "std")]
//extern crate std;

mod consts;
mod shabal;

pub use digest::Digest;
pub use shabal::{Shabal192, Shabal224, Shabal256, Shabal384, Shabal512};

extern crate libc;
use std::ffi::CStr;
use std::io::prelude::*;
use std::fs::OpenOptions;
use std::str;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;


fn print_result(sum: &[u8], name: &str) -> Vec<u8> {
    let mut vec = Vec::new();
    for byte in sum {
//        print!("{1:02x}{0}", "  ", byte);
        vec.push(*byte);
    }
//    println!("\t{0}\tlength:{1}", name, sum.len());
    return vec;
}

#[no_mangle]
pub extern "C" fn shabal256(nonce_nrbuff: *const libc::c_char, pubkeybuff: *const libc::c_char) {
    let buf_name1 = unsafe { CStr::from_ptr(nonce_nrbuff).to_bytes() };
    let str_name1 = String::from_utf8(buf_name1.to_vec()).unwrap();

    let buf_name2 = unsafe { CStr::from_ptr(pubkeybuff).to_bytes() };
    let str_name2 = String::from_utf8(buf_name2.to_vec()).unwrap();

    let str_name = str_name2 + &str_name1;
    let mut sh = Shabal256::default();
    sh.input(str_name);

    let filename = "./Cache/shall".to_string() + &str_name1;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .append(true)
        .open(filename);

    match file {
        Ok(mut stream) => {
            stream.write(&sh.result());
        }
        Err(err) => {
            println!("{:?}", err);
        }
    }
}

#[no_mangle]
pub extern "C" fn shabal512(nonce_nrbuff: *const libc::c_char, pubkeybuff: *const libc::c_char) {
    let buf_name1 = unsafe { CStr::from_ptr(nonce_nrbuff).to_bytes() };
    let str_name1 = String::from_utf8(buf_name1.to_vec()).unwrap();

    let buf_name2 = unsafe { CStr::from_ptr(pubkeybuff).to_bytes() };
    let str_name2 = String::from_utf8(buf_name2.to_vec()).unwrap();

    let str_name = str_name2 + &str_name1;
    let mut sh = Shabal512::default();
    sh.input(str_name);

    let filename = "./Cache/shall".to_string() + &str_name1;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .append(true)
        .open(filename);

    match file {
        Ok(mut stream) => {
            stream.write(&sh.result());
        }
        Err(err) => {
            println!("{:?}", err);
        }
    }
}

#[no_mangle]
pub extern "C" fn genNonce256(nonce_nrbuff: *const libc::c_char, pubkeybuff: *const libc::c_char, filepath: *const libc::c_char) {
    let buf_name1 = unsafe { CStr::from_ptr(nonce_nrbuff).to_bytes() };
    let str_name1 = String::from_utf8(buf_name1.to_vec()).unwrap();

    let buf_name2 = unsafe { CStr::from_ptr(pubkeybuff).to_bytes() };
    let str_name2 = String::from_utf8(buf_name2.to_vec()).unwrap();

    let buf_filepath = unsafe { CStr::from_ptr(filepath).to_bytes() };
    let str_filepath = String::from_utf8(buf_filepath.to_vec()).unwrap();

    let mut book_reviews: HashMap<usize, Vec<u8>> = HashMap::new();
    {
        let mut str_name = str_name2.clone() + &str_name1.clone();
        let mut num = 8191;
        for _i in 0..8192 {
            if str_name.len() + 32 >= 4096 {
                if book_reviews.len() >= 128 {
                    let mut pre_str = String::from("");
                    for i in 0..128 {
                        if book_reviews.contains_key(&(num + 1 + i)) {
                            let aa = book_reviews.get(&(num + 1 + i)).unwrap();
                            pre_str.insert_str(0, unsafe{ &String::from_utf8_unchecked(aa.to_vec()) });
                        }
                    }
                    let mut sh = Shabal256::default();
                    sh.input(pre_str.clone());
                    let pre_result = print_result(&sh.result(), "shabal256");
                    book_reviews.insert(
                        num, pre_result
                    );
                } else {
                    let mut pre_str = String::from("");
                    for i in 0..book_reviews.len() {
                        if book_reviews.contains_key(&(num + 1 + i)) {
                            let aa = book_reviews.get(&(num + 1 + i)).unwrap();
                            pre_str.insert_str(0,  unsafe{ &String::from_utf8_unchecked(aa.to_vec()) });
                        }
                    }
                    let mut sh = Shabal256::default();
                    sh.input(pre_str.clone());
                    let pre_result = print_result(&sh.result(), "shabal256");
                    book_reviews.insert(
                        num, pre_result
                    );
                }
                num = num - 1;
            } else {
                let mut sh = Shabal256::default();
                sh.input(str_name.clone());
                let result = print_result(&sh.result(), "shabal256");
                let str_result = unsafe{ String::from_utf8_unchecked(result.clone()) };
                book_reviews.insert(
                    num, result
                );
                str_name = str_result + &str_name;
                num = num-1;
            }
        }
    }

    let mut final_str = str_name2 + &str_name1;
    for i in 0..8192 {
        if book_reviews.contains_key(&(8191 - i)) {
            let aa = book_reviews.get(&(8191 - i)).unwrap();
            final_str.insert_str(0, unsafe{ &String::from_utf8_unchecked(aa.to_vec()) });
        }
    }
    let mut sh = Shabal256::default();
    sh.input(final_str.clone());
    let final_result = print_result(&sh.result(), "shabal256");

    for i in 0..8192 {
        if book_reviews.contains_key(&(8191 - i)) {
            let aa = book_reviews.get(&(8191 - i)).unwrap();
            let mut vec: Vec<u8> = Vec::new();
            if aa.len() == 32 && final_result.len() == 32 {
                for j in 0..32 {
                    vec.push((aa[j] ^ final_result[j]).to_ascii_lowercase());
                }

                let filename = str_filepath.clone() + &"/Cache".to_string() + &str_name1;
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .append(true)
                    .open(filename);

                match file {
                    Ok(mut stream) => {
                        stream.write(vec.as_slice());
                    }
                    Err(err) => {
                        println!("{:?}", err);
                    }
                }
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn genNonce512(nonce_nrbuff: *const libc::c_char, pubkeybuff: *const libc::c_char, filepath: *const libc::c_char) {
    let buf_name1 = unsafe { CStr::from_ptr(nonce_nrbuff).to_bytes() };
    let str_name1 = String::from_utf8(buf_name1.to_vec()).unwrap();

    let buf_name2 = unsafe { CStr::from_ptr(pubkeybuff).to_bytes() };
    let str_name2 = String::from_utf8(buf_name2.to_vec()).unwrap();

    let buf_filepath = unsafe { CStr::from_ptr(filepath).to_bytes() };
    let str_filepath = String::from_utf8(buf_filepath.to_vec()).unwrap();

    let mut book_reviews: HashMap<usize, Vec<u8>> = HashMap::new();
    {
        let mut str_name = str_name2.clone() + &str_name1.clone();
        let mut num = 8191;
        for _i in 0..8192 {
            if str_name.len() + 32 >= 4096 {
                if book_reviews.len() >= 128 {
                    let mut pre_str = String::from("");
                    for i in 0..128 {
                        if book_reviews.contains_key(&(num + 1 + i)) {
                            let aa = book_reviews.get(&(num + 1 + i)).unwrap();
                            pre_str.insert_str(0, unsafe{ &String::from_utf8_unchecked(aa.to_vec()) });
                        }
                    }
                    let mut sh = Shabal512::default();
                    sh.input(pre_str.clone());
                    let pre_result = print_result(&sh.result(), "Shabal512");
                    book_reviews.insert(
                        num, pre_result
                    );
                } else {
                    let mut pre_str = String::from("");
                    for i in 0..book_reviews.len() {
                        if book_reviews.contains_key(&(num + 1 + i)) {
                            let aa =  book_reviews.get(&(num + 1 + i)).unwrap();
                            pre_str.insert_str(0,  unsafe{ &String::from_utf8_unchecked(aa.to_vec()) });
                        }
                    }
                    let mut sh = Shabal512::default();
                    sh.input(pre_str.clone());
                    let pre_result = print_result(&sh.result(), "Shabal512");
                    book_reviews.insert(
                        num, pre_result
                    );
                }
                num = num - 1;
            } else {
                let mut sh = Shabal512::default();
                sh.input(str_name.clone());
                let result = print_result(&sh.result(), "Shabal512");
                let str_result = unsafe{ String::from_utf8_unchecked(result.clone()) };
                book_reviews.insert(
                    num, result
                );
                str_name = str_result + &str_name;
                num = num-1;
            }
        }
    }

    let mut final_str = str_name2 + &str_name1;
    for i in 0..8192 {
        if book_reviews.contains_key(&(8191 - i)) {
            let aa = book_reviews.get(&(8191 - i)).unwrap();
            final_str.insert_str(0, unsafe{ &String::from_utf8_unchecked(aa.to_vec()) });
        }
    }
    let mut sh = Shabal512::default();
    sh.input(final_str.clone());
    let final_result = print_result(&sh.result(), "Shabal512");

    for i in 0..8192 {
        if book_reviews.contains_key(&(8191 - i)) {
            let aa = book_reviews.get(&(8191 - i)).unwrap();
            let mut vec: Vec<u8> = Vec::new();
            if aa.len() == 32 && final_result.len() == 32 {
                for j in 0..32 {
                    vec.push((aa[j] ^ final_result[j]).to_ascii_lowercase());
                }

                let filename = str_filepath.clone() + &"/Cache".to_string() + &str_name1;
                let file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create(true)
                    .append(true)
                    .open(filename);

                match file {
                    Ok(mut stream) => {
                        stream.write(vec.as_slice());
                    }
                    Err(err) => {
                        println!("{:?}", err);
                    }
                }
            }
        }
    }
}

#[no_mangle]
pub extern "C" fn genHash_Target256(presig: *const libc::c_char, pregenerator: *const libc::c_char, blockheigh: *const libc::c_char, nonce_nrfilepath: *const libc::c_char, nonce_nrfilename: *const libc::c_char) {
    let nonce_nrfilepath_buff = unsafe { CStr::from_ptr(nonce_nrfilepath).to_bytes() };
    let str_nonce_nrfilepath = String::from_utf8(nonce_nrfilepath_buff.to_vec()).unwrap();

    let nonce_nrfilename_buff = unsafe { CStr::from_ptr(nonce_nrfilename).to_bytes() };
    let str_nonce_nrfilename = String::from_utf8(nonce_nrfilename_buff.to_vec()).unwrap();

    let blockheigh_buff = unsafe { CStr::from_ptr(blockheigh).to_bytes() };
    let str_blockheigh = String::from_utf8(blockheigh_buff.to_vec()).unwrap();

    let paths = fs::read_dir(str_nonce_nrfilepath.clone() + "/").unwrap();
    for path in paths {
        if path.unwrap().path().to_path_buf() == PathBuf::from(str_nonce_nrfilepath.clone() + "/" + &str_nonce_nrfilename) {
            let contents = fs::read(str_nonce_nrfilepath.clone() + "/" + &str_nonce_nrfilename).unwrap();
            if contents.len() != 262144 {
                return;
            }
            let mut scoops: HashMap<usize, Vec<u8>> = HashMap::new();
            for i in 0..4096 {
                scoops.insert(
                    i, contents.get(i*64..(i+1)*64).unwrap().to_vec()
                );
            }

            let buf_name1 = unsafe { CStr::from_ptr(presig).to_bytes() };
            let str_name1 = String::from_utf8(buf_name1.to_vec()).unwrap();

            let buf_name2 = unsafe { CStr::from_ptr(pregenerator).to_bytes() };
            let str_name2 = String::from_utf8(buf_name2.to_vec()).unwrap();

            let str_name = str_name2 + &str_name1;
            let mut sh = Shabal256::default();
            sh.input(str_name);
            let newgensig = print_result(&sh.result(), "shabal256");

            let mut sh = Shabal256::default();
            // genhash
            sh.input( str_blockheigh.clone() + unsafe{ &String::from_utf8_unchecked(newgensig.clone()) } );
            let mut noncenum: usize = 0;
            for byte in &sh.result() {
                let byteint = *byte as usize;
                noncenum = noncenum + byteint;
            }
            let scoop = &scoops[&(noncenum/4096)];
            let mut sh = Shabal256::default();
            sh.input(unsafe { String::from_utf8_unchecked(scoop.to_vec()) } + unsafe{ &String::from_utf8_unchecked(newgensig) });

            let filename = str_nonce_nrfilepath + "/target" + &str_blockheigh;
            let file = OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .append(true)
                .open(filename);

            match file {
                Ok(mut stream) => {
                    stream.write(&sh.result());
                }
                Err(err) => {
                    println!("{:?}", err);
                }
            }
            break;
        }
    }
}

#[no_mangle]
pub extern "C" fn genHash_Target512(presig: *const libc::c_char, pregenerator: *const libc::c_char, blockheigh: *const libc::c_char, nonce_nrfilepath: *const libc::c_char, nonce_nrfilename: *const libc::c_char) {
    let nonce_nrfilepath_buff = unsafe { CStr::from_ptr(nonce_nrfilepath).to_bytes() };
    let str_nonce_nrfilepath = String::from_utf8(nonce_nrfilepath_buff.to_vec()).unwrap();

    let nonce_nrfilename_buff = unsafe { CStr::from_ptr(nonce_nrfilename).to_bytes() };
    let str_nonce_nrfilename = String::from_utf8(nonce_nrfilename_buff.to_vec()).unwrap();

    let blockheigh_buff = unsafe { CStr::from_ptr(blockheigh).to_bytes() };
    let str_blockheigh = String::from_utf8(blockheigh_buff.to_vec()).unwrap();

    let contents = fs::read(str_nonce_nrfilepath.clone() + "/" + &str_nonce_nrfilename).unwrap();
    if contents.len() != 262144 {
        return;
    }
    let mut scoops: HashMap<usize, Vec<u8>> = HashMap::new();
    for i in 0..4096 {
        scoops.insert(
            i, contents.get(i*64..(i+1)*64).unwrap().to_vec()
        );
    }

    let buf_name1 = unsafe { CStr::from_ptr(presig).to_bytes() };
    let str_name1 = String::from_utf8(buf_name1.to_vec()).unwrap();

    let buf_name2 = unsafe { CStr::from_ptr(pregenerator).to_bytes() };
    let str_name2 = String::from_utf8(buf_name2.to_vec()).unwrap();

    let str_name = str_name2 + &str_name1;
    let mut sh = Shabal512::default();
    sh.input(str_name);
    let newgensig = print_result(&sh.result(), "shabal512");

    let mut sh = Shabal512::default();
    // genhash
    sh.input( str_blockheigh.clone() + unsafe{ &String::from_utf8_unchecked(newgensig.clone()) } );
    let mut noncenum: usize = 0;
    for byte in &sh.result() {
        let byteint = *byte as usize;
        noncenum = noncenum + byteint;
    }
    let scoop = &scoops[&(noncenum/4096)];
    let mut sh = Shabal512::default();
    sh.input(unsafe { String::from_utf8_unchecked(scoop.to_vec()) } + unsafe{ &String::from_utf8_unchecked(newgensig) });

    let filename = str_nonce_nrfilepath + "/target" + &str_blockheigh;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .append(true)
        .open(filename);

    match file {
        Ok(mut stream) => {
            stream.write(&sh.result());
        }
        Err(err) => {
            println!("{:?}", err);
        }
    }
}
