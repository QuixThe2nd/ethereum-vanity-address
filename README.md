# Ethereum Vanity Address
This script generates ethereum vanity addresses from 12 word mnemonics.

The script runs indefinitely, logging the best addresses found, judged by the number of 0 bytes (2 `0`s in a row).
This script is based off [Viem](https://github.com/wevm/viem), with only the required logic extracted to significantly improve speed.

Changes made to Viems logic include removing all error handling, removing case sensitivity, and removing many checks. A lot of logic is hardcoded to reduce the number of operations needed to generate an address.
