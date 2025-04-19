# Ethereum Vanity Address
This script generates ethereum vanity addresses from 12 word mnemonics.

The script runs indefinitely, logging the best addresses found, judged by duplicate characters at start or end. For example (0x000..., 0x111..., 0x...000, or 0x...111).
This script is based off [Viem](https://github.com/wevm/viem), with only the required logic extracted to significantly improve speed.

Changes made to Viems logic include removing all error handling, removing case sensitivity, and removing many checks. A lot of logic is hardcoded to reduce the number of operations needed to generate an address.
