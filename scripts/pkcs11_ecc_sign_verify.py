#
# Copyright 2023 NXP
# SPDX-License-Identifier: Apache-2.0
#
"""

Generates keys of type ECC and performs sign and verify operations

"""

from pkcs11_utils import *

def main():
    args = parse_in_ec_args()
    if args is None:
        return
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    log.info("Generating keypair: %s" % (args.key_type))
    run("%s --module %s --keypairgen --key-type  %s --label sss:0xEF000001" % (pkcs11_tool, module_path, args.key_type))
    log.info("###################################################")

    log.info("Retrieving Public Key")
    run("%s --module %s --read-object --type pubkey --label sss:0xEF000001 -o %s%s_0xEF000001_public.key" % (pkcs11_tool, module_path, output_dir, args.key_type.split(":")[1]))
    log.info("###################################################")

    data_len = ["10","20","28","32","48","64"]
    for len in data_len:
        log.info("Signing data with length %s and with key: %s and algo: ECDSA" % (len, args.key_type))
        run("%s --module %s --sign --mechanism ECDSA --label sss:0xEF000001 --input-file %sdata%s.txt -o %sout_ECDSA_input_%s_%s.sign" % (pkcs11_tool, module_path, input_dir, len, output_dir, len, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Verifying data with length %s and with key: %s and algo: ECDSA" % (len, args.key_type))
        run("%s --module %s --verify --mechanism ECDSA --label sss:0xEF000001 --input-file %sdata%s.txt --signature-file %sout_ECDSA_input_%s_%s.sign" % (pkcs11_tool, module_path, input_dir, len, output_dir, len, args.key_type.split(":")[1]))
        log.info("###################################################")


    sha_types = ["ECDSA-SHA1", "ECDSA-SHA224", "ECDSA-SHA256","ECDSA-SHA384","ECDSA-SHA512"]
    for sha_type in sha_types:
        log.info("Signing data with length = 600 and with key: %s and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --sign --mechanism %s --label sss:0xEF000001 --input-file %sdata600.txt -o %sout_%s_input_600_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Verifying data with length = 600 and with key: %s and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --verify --mechanism %s --label sss:0xEF000001 --input-file %sdata600.txt --signature-file %sout_%s_input_600_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")


        log.info("Signing data with length = 1024 and with key: %s and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --sign --mechanism %s --label sss:0xEF000001 --input-file %sdata1024.txt -o %sout_%s_input_600_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Verifying data with length = 1024 and with key: %s and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --verify --mechanism %s --label sss:0xEF000001 --input-file %sdata1024.txt --signature-file %sout_%s_input_600_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")


        log.info("Signing data with length = 2048 and with key: %s and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --sign --mechanism %s --label sss:0xEF000001 --input-file %sdata2048.txt -o %sout_%s_input_600_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")

        log.info("Verifying data with length = 2048 and with key: %s and algo: %s" % (args.key_type, sha_type))
        run("%s --module %s --verify --mechanism %s --label sss:0xEF000001 --input-file %sdata2048.txt --signature-file %sout_%s_input_600_%s.sign" % (pkcs11_tool, module_path, sha_type, input_dir, output_dir, sha_type, args.key_type.split(":")[1]))
        log.info("###################################################")


    log.info("Deleting generated keypair")
    run("%s --module %s --delete-object --type privkey --label sss:0xEF000001" % (pkcs11_tool, module_path))
    log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()