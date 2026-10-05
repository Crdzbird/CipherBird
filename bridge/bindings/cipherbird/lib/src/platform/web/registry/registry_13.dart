part of '../web_platform.dart';

final Map<String, Function> _registry13 = {
  'cryptolib_box_encrypt':
      (
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> recipientPub,
        int rpubLen,
        Pointer<NativeType> senderSec,
        int ssecLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_box_encrypt',
        [
          plaintext.address.toJS,
          ptLen.toJS,
          recipientPub.address.toJS,
          rpubLen.toJS,
          senderSec.address.toJS,
          ssecLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_box_decrypt':
      (
        Pointer<NativeType> ciphertext,
        int ctLen,
        Pointer<NativeType> senderPub,
        int spubLen,
        Pointer<NativeType> recipientSec,
        int rsecLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_box_decrypt',
        [
          ciphertext.address.toJS,
          ctLen.toJS,
          senderPub.address.toJS,
          spubLen.toJS,
          recipientSec.address.toJS,
          rsecLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_sealedbox_encrypt':
      (
        Pointer<NativeType> plaintext,
        int ptLen,
        Pointer<NativeType> recipientPub,
        int rpubLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_sealedbox_encrypt',
        [
          plaintext.address.toJS,
          ptLen.toJS,
          recipientPub.address.toJS,
          rpubLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_sealedbox_decrypt':
      (
        Pointer<NativeType> ciphertext,
        int ctLen,
        Pointer<NativeType> recipientPub,
        int rpubLen,
        Pointer<NativeType> recipientSec,
        int rsecLen,
      ) => WebEngine.current.callStruct(
        '_cbw_cryptolib_sealedbox_decrypt',
        [
          ciphertext.address.toJS,
          ctLen.toJS,
          recipientPub.address.toJS,
          rpubLen.toJS,
          recipientSec.address.toJS,
          rsecLen.toJS,
        ],
        CipherBirdBufferResult.size,
        CipherBirdBufferResult._new,
      ),
  'cryptolib_vault_create':
      (Pointer<NativeType> masterKey, int mkLen, int kdfPreset) =>
          Pointer<Void>._(
            WebEngine.current.callInt('_cbw_cryptolib_vault_create', [
              masterKey.address.toJS,
              mkLen.toJS,
              kdfPreset.toJS,
            ]),
          ),
};
