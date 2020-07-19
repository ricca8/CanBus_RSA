# CanBus_RSA


Writes a message and its signature, created through RSA (by openssl) with private key, on can bus, dividing it into frames. A reader will take frames from can bus, reform the message and signature, and  check validity through public key of writer

USE CMAKE, g++ gives problems.
