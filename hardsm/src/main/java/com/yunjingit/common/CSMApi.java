package com.yunjingit.common;

import com.sun.jna.Library;

public interface CSMApi extends Library {
    int api_init(byte[] out);

    int api_final(byte[] out);

    int api_print_context(int verbose, byte[] out);

    int api_ctx_info(byte[] out);

    int api_login_device(int deviceIndex, String pinCode, byte[] out);

    int api_login_device_pipe(int deviceIndex, String pinCode, byte[] out, int pipe);

    int api_logout_device(int deviceIndex, byte[] out);

    int api_device_status(int device_index, byte[] out);

    int api_protect_key(int flag, byte[] out);

    int api_digest(int device_index, int pipe_index, byte[] data, int data_len, byte[] out);

    int api_digest_init(int device_index, int pipe_index, byte[] out);

    int api_digest_update(int device_index, int pipe_index, byte[] data, int data_len, byte[] out);

    int api_digest_final(int device_index, int pipe_index, byte[] data, int data_len, byte[] out);

    int api_random(int device_index, int pipe_index, int length, byte[] out);

    int api_generate_key(int device_index, int pipe_index, byte[] out);

    int api_generate_keypair(int device_index, int pipe_index, byte[] out);

    int api_encrypt(int device_index, int pipe_index, String hex_key, String hex_iv,
                    byte[] data, int data_len, byte[] out);

    int api_decrypt(int device_index, int pipe_index, String hex_key, String hex_iv,
                    byte[] data, int data_len, byte[] out);

    int api_encrypt_init(int device_index, int pipe_index, String hex_key, String hex_iv, byte[] out);

    int api_encrypt_update(int device_index, int pipe_index, byte[] data, int data_len, byte[] out);

    int api_encrypt_final(int device_index, int pipe_index, byte[] data, int data_len, byte[] out);

    int api_decrypt_init(int device_index, int pipe_index, String hex_key, String hex_iv, byte[] out);

    int api_decrypt_update(int device_index, int pipe_index, byte[] data, int data_len, byte[] out);

    int api_decrypt_final(int device_index, int pipe_index, byte[] data, int data_len, byte[] out);

    int api_sign(int device_index, int pipe_index, String hex_key, String hex_data, byte[] out);

    int api_verify(int device_index, int pipe_index, String hex_key, String hex_data, String hex_signature, byte[] out);

    int api_sm2decrypt(int device_index, int pipe_index, String hex_key, String hex_data, byte[] out);
    int api_sm2encrypt(int device_index, int pipe_index, String hex_key, String hex_data, byte[] out);
}
