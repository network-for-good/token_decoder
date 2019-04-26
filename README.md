# TokenDecoder
## Using public/private keys
This token will have to have been produced using a private primary or secondary key that relates to the public keys stored in the public_key_certs folder.

There is a primary and secondar for production and another set for all other environments.

## Using a hmac_secret
This token must have been generated using a shared hmac_secret.

This secret must have been set as a class instance variable on the TokenDecoder class on initialization.

An example of this assignment is below.
`TokenDecoder::Decoder.hmac_secret = APP_CONFIG[:hmac_secret]`