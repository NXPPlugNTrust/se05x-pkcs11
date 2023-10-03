#
# Copyright 2023 NXP
# SPDX-License-Identifier: Apache-2.0
#

"""
Generates keys of type ECC
"""

from pkcs11_utils import *

def main():
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    keys = {"EC:prime192v1":"0xEF000001", "EC:prime256v1":"0xEF000002", "EC:secp384r1":"0xEF000003", "EC:secp521r1":"0xEF000004"}

    for key_type in keys:
        log.info("Generating keypair: %s" % (key_type))
        run("%s --module %s --keypairgen --key-type  %s --label sss:%s" % (pkcs11_tool, module_path, key_type, keys[key_type]))
        log.info("###################################################")

        log.info("Retrieving Public Key")
        run("%s --module %s --read-object --type pubkey --label sss:%s -o %s%s_%s_public.key" % (pkcs11_tool, module_path, keys[key_type], output_dir, key_type.split(":")[1], keys[key_type]))
        log.info("###################################################")

        log.info("Deleting generated keypair")
        run("%s --module %s --delete-object --type privkey --label sss:%s" % (pkcs11_tool, module_path, keys[key_type]))
        log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()