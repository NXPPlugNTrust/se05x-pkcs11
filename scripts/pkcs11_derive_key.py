#
# Copyright 2024 NXP
# SPDX-License-Identifier: Apache-2.0
#

"""
Generates derive key
"""

from pkcs11_utils import *

def main():
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    keys = {"EC:prime192v1":"0xEF000001","EC:prime256v1":"0xEF000002"}

    for key_type in keys:
        log.info("Generating keypair: %s" % (key_type))
        run("%s --module %s --keypairgen --key-type  %s --label sss:%s" % (pkcs11_tool, module_path, key_type, keys[key_type]))
        log.info("###################################################")

        log.info("Retrieving Public Key")
        run("%s --module %s --read-object --type pubkey --label sss:%s -o %s%s_%s_public.key" % (pkcs11_tool, module_path, keys[key_type], output_dir, key_type.split(":")[1], keys[key_type]))
        log.info("###################################################")

        log.info("create shared secret")
        run("%s --module %s --derive --mechanism ECDH1-DERIVE --label sss:%s --input-file %s%s_%s_public.key -o %sshared.key" % (pkcs11_tool, module_path,keys[key_type],output_dir, key_type.split(":")[1], keys[key_type],output_dir))

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