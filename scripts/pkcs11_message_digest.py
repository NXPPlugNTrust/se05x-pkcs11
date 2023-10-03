#
# Copyright 2023 NXP
# SPDX-License-Identifier: Apache-2.0
#
"""

Generates digest of some data using different algorithms

"""

from pkcs11_utils import *

def main():
    if not os.path.exists(output_dir):
        os.mkdir(output_dir)

    log.info("Digest with SHA-1")
    run("%s --module %s --hash --mechanism SHA-1 --input-file %sdata.txt --output-file %sout_hash_sha1.txt" % (pkcs11_tool, module_path, input_dir, output_dir))
    log.info("###################################################")

    log.info("Digest with SHA224")
    run("%s --module %s --hash --mechanism SHA224 --input-file %sdata32.txt --output-file %sout_hash_sha224.txt" % (pkcs11_tool, module_path, input_dir, output_dir))
    log.info("###################################################")

    log.info("Digest with SHA256")
    run("%s --module %s --hash --mechanism SHA256 --input-file %sdata1024.txt --output-file %sout_hash_sha256.txt" % (pkcs11_tool, module_path, input_dir, output_dir))
    log.info("###################################################")

    log.info("Digest with SHA384")
    run("%s --module %s --hash --mechanism SHA384 --input-file %sdata600.txt --output-file %sout_hash_sha384.txt" % (pkcs11_tool, module_path, input_dir, output_dir))
    log.info("###################################################")

    log.info("Digest with SHA512")
    run("%s --module %s --hash --mechanism SHA512 --input-file %sdata64.txt --output-file %sout_hash_SHA512.txt" % (pkcs11_tool, module_path, input_dir, output_dir))
    log.info("###################################################")

    log.info("##############################################################")
    log.info("#                                                            #")
    log.info("#            Program completed successfully                  #")
    log.info("#                                                            #")
    log.info("##############################################################")

if __name__ == '__main__':
    main()
