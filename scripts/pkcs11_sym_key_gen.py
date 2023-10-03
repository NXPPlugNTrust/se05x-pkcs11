#
# Copyright 2023 NXP
# SPDX-License-Identifier: Apache-2.0
#

"""
Generates symmetric key of type AES
"""

from pkcs11_utils import *

def main():
    keys = ["aes:16", "aes:24", "aes:32"]
    for key in keys:
        log.info("Generating symmetric key: %s.. (Generates random data and set key)" % (key))
        run("%s --module %s --keygen --key-type %s --label sss:0xEF00000B" % (pkcs11_tool, module_path, key))
        log.info("###################################################")

        log.info("Deleting Key")
        run("%s --module %s --delete-object --type secrkey --label sss:0xEF00000B" % (pkcs11_tool, module_path))
        log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()