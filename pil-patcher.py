#! /usr/bin/env python

import sys
import struct
import os
import os.path
import string
import optparse
import shutil
import hashlib

options = None

def setup():
  global options
  parser = optparse.OptionParser("usage: %prog [options] \n" +
                                 "Try %prog -h' for more information.")

  parser.add_option("-m", "--module", dest="prefix",
                    default="modem", type="string",
                    help="Module name (prefix)")

  parser.add_option("-r", "--remove-sign", dest="rm_sign",
                    default=0, type="int",
                    help="Remove sign (1 - simple, 2 - strong)")

  parser.add_option("-u", "--update-hash", dest="upd_hash",
                    action="store_true", default=False,
                    help="Update hash table after editing binaries")

  (options, args) = parser.parse_args()
    
def die(message):
  print message
  exit(1)

def gen_struct(format, image):
  str = "<%s" % "".join([x[1] for x in format])
  elems = struct.unpack(str, image.read(struct.calcsize(str)))
  keys = [x[0] for x in format]
  return dict(zip(keys, elems))

def get_struct_size(format):
  str = "<%s" % "".join([x[1] for x in format])
  return struct.calcsize(str)

elf32_hdr = [
    ("ident", "16s"),
    ("type", "H"),
    ("machine", "H"),
    ("version", "I"),
    ("entry", "I"),
    ("phoff", "I"),
    ("shoff", "I"),
    ("flags", "I"),
    ("ehsize", "H"),
    ("phentsize", "H"),
    ("phnum", "H"),
    ("shentsize", "H"),
    ("shnum", "H"),
    ("shstrndx", "H"),
    ]

elf32_phdr = [
    ("type", "I"),
    ("offset", "I"),
    ("vaddr", "I"),
    ("paddr", "I"),
    ("filesz", "I"),
    ("memsz", "I"),
    ("flags", "I"),
    ("align", "I"),
    ]

hash_hdr = [
    ("image_id", "I"),
    ("flash_parti_ver", "I"),
    ("image_src", "I"),
    ("image_dest_ptr", "I"),
    ("image_size", "I"),
    ("code_size", "I"),
    ("sig_ptr", "I"),
    ("sig_size", "I"),
    ("cert_chain_ptr", "I"),
    ("cert_chain_size", "I"),
    ]
    
def parse_metadata(image):
  global options, elf32_hdr, elf32_phdr, hash_hdr
  metadata = {}

  elf32_hdr = gen_struct(elf32_hdr, image)
  metadata['num_segments'] = elf32_hdr['phnum']
  metadata['pg_start'] = elf32_hdr['phoff']

  metadata['segments'] = []
  seg_count = metadata['num_segments'] 
  pg_start = metadata['pg_start']
  for i in xrange(seg_count):
    image.seek(pg_start + (i * elf32_hdr['phentsize']))
    phdr = gen_struct(elf32_phdr, image)
    metadata['segments'].append(phdr)
    phdr['hash'] = (phdr['flags'] & (0x7 << 24)) == (0x2 << 24)
    phdr['num'] = i
    offset = pg_start + seg_count * elf32_hdr['phentsize'] + get_struct_size(hash_hdr)
    image.seek(offset + i * 32)
    phdr['stor_hash'] = image.read(32)
    #print "[" + "%02d" % i + "] stor_hash =","".join("{:02x}".format(ord(c)) for c in phdr['stor_hash'])
    phdr['real_hash'] = None

  return metadata

def is_elf(file):
  file.seek(0)
  magic = file.read(4)
  file.seek(0)
  return magic == '\x7fELF'

def parse_mdt():
  global options
  mdt_fn = './' + options.prefix + '.mdt'
  if not os.path.isfile(mdt_fn):
    die("ERROR: Can't found file " + mdt_fn)
  image = open(mdt_fn, 'rb')
  if not is_elf(image):
    die("ERROR: file " + mdt_fn + " without ELF header")
  metadata = parse_metadata(image)
  image.close()
  return metadata

def get_file_sha256(fn):
  f = open(fn, 'rb')
  f.seek(0)
  hash_object = hashlib.sha256(f.read())
  f.close()
  return hash_object.digest()
  
def sec_file_clean(fn):
  orig_suffix = '_orig'
  if (os.path.isfile(fn + orig_suffix)):
    shutil.copy2(fn + orig_suffix, fn)

def remove_sign(image, offset):  
  global options, hash_hdr
  image.seek(offset)
  sechdr = gen_struct(hash_hdr, image)
  hdr_size = get_struct_size(hash_hdr)
  #print "  hash sec: header size = 0x%x" % hdr_size
  print "  hash sec: sig_size = 0x%x" % sechdr['sig_size']
  if (sechdr['sig_size'] == 0):
    die("ERROR: sing already removed !!!")

  sechdr['image_size'] = sechdr['code_size']
  sechdr['sig_size'] = 0
  sechdr['cert_chain_ptr'] = sechdr['sig_ptr']
  sechdr['cert_chain_size'] = 0
  
  image.seek(offset)
  image.write(struct.pack("I", sechdr['image_id']))
  image.write(struct.pack("I", sechdr['flash_parti_ver']))
  image.write(struct.pack("I", sechdr['image_src']))
  image.write(struct.pack("I", sechdr['image_dest_ptr']))
  image.write(struct.pack("I", sechdr['image_size']))
  image.write(struct.pack("I", sechdr['code_size']))
  image.write(struct.pack("I", sechdr['sig_ptr']))
  image.write(struct.pack("I", sechdr['sig_size']))
  image.write(struct.pack("I", sechdr['cert_chain_ptr']))
  image.write(struct.pack("I", sechdr['cert_chain_size']))
  
  if (options.rm_sign == 2):
    image.seek(offset + sechdr['code_size'] + get_struct_size(hash_hdr))
    image.truncate()  

def update_sec_hash(image, offset, sec_num, hash):
  global hash_hdr
  image.seek(offset)
  sechdr = gen_struct(hash_hdr, image)
  hdr_size = get_struct_size(hash_hdr)
  image.seek(offset + hdr_size + sec_num * 32)
  image.write(hash)
    
#----------------------------------------------  

setup()

mdt_fn = './' + options.prefix + '.mdt'
sec_file_clean(mdt_fn)
sec_file_clean(options.prefix + '.b00')
sec_file_clean(options.prefix + '.b01')

metadata = parse_mdt()

print "sec count:",metadata['num_segments']

elf_fn = None
hash_fn = None

for i, seg in enumerate(metadata['segments']):
  offset = seg['offset']
  filesz = seg['filesz']
  #print "["+str(i)+"] offset =",offset," size =",filesz
  if (filesz == 1 and seg['memsz'] == 1 and seg['align'] == 1):
    #print "  skip INTERP section"
    continue
  sec_fn = "./%s.b%02d" % (options.prefix, seg['num'])
  sec_exist = os.path.isfile(sec_fn)
  if (filesz > 0 and not sec_exist):
    die("Error: 001 %d" % filesz)
  if (not sec_exist):
    continue
  if (seg['num'] == 0):
    elf_fn = sec_fn
    elf_seg = seg
    print "elf  file:",sec_fn," offset =",offset," size =",filesz
  if (seg['hash']):
    hash_fn = sec_fn
    hash_seg = seg
    print "hash file:",sec_fn," offset =",offset," size =",filesz

if (elf_fn == None):
  die("Can't found header file")

if (metadata['num_segments'] == 1 and options.prefix == 'mba'):
  print "---------- Remove sign (MBA) -----------"
  elf_file = open(elf_fn, 'r+b')
  elf_file.seek(0)
  sign_hdr = "\xC0\xE0\xFB\xE0\x04\x00\x82\xEC" + \
             "\x14\x84\x2C\xE0\x24\x84\x2C\xE0" + \
             "\x30\x84\x2C\xE0\x10\x84\x2C\xE0" + \
             "\xF0\xC3\xFB\xE0\xFF\xFF\xFF\x00"
  data = elf_file.read()
  pos = data.find(sign_hdr)
  if (pos < 0x1000):
    die("ERROR: Can't found sign header")
  print "sign header pos = 0x%08x" % pos
  print "Patch:",elf_fn
  elf_file.seek(pos + len(sign_hdr))
  elf_file.truncate()
  elf_file.write("\x00\x10\x03\x00\x6D\x56\x01\x40\x00\xA3\x9D\xEC\x00\xA2\x9D\xEC")
  elf_file.write("\x5F\xF3\x6E\x3C\x0D\x66\x19\x00\x00\x00\x00\x00\x00\x00\x00\x00")
  elf_file.write("\x00\x00\x00\x00\x00\x00\xF0\x3F\x00\x00\x00\x00\x84\xD7\x97\x41")
  elf_file.write("\x00\x00\x00\x00\x00\x00\x24\x40\x00\x00\x00\x00\x00\x00\xE0\xBF")
  elf_file.write("\x00\x00\x00\x00\x00\x00\xF8\x3F\x00\x00\x00\x00\x00\x00\xF0\xBF")
  elf_file.close()
  
  elf_file_size = os.path.getsize(elf_fn)
  
  print "Patch:",mdt_fn
  mdt_file = open(mdt_fn, 'r+b')
  mdt_file.seek(0x07)
  mdt_file.write('\x00')  # EI_OSABI (Operating system/ABI identification)
  mdt_file.seek(0x44)
  mdt_file.write(struct.pack("I", elf_file_size))
  mdt_file.seek(0x48)
  mdt_file.write(struct.pack("I", elf_file_size))
  mdt_file.close()

  exit(0)

if (hash_fn == None):
  die("Can't found hash section file")
  
if (options.rm_sign > 0):
  print "---------- Remove sign (1) -------------"
  print "Patch:",hash_fn
  hash_file = open(hash_fn, 'r+b')
  remove_sign(hash_file, 0)
  hash_file.close()

  hash_file_size = os.path.getsize(hash_fn)

  print "Patch:",mdt_fn
  mdt_file = open(mdt_fn, 'r+b')
  hs_offset = metadata['pg_start'] + 32 * metadata['num_segments']
  remove_sign(mdt_file, hs_offset)
  mdt_file.close()

if (options.rm_sign == 2):
  print "---------- Remove sign (2) -------------"
  elf_file = open(elf_fn, 'r+b')
  elf_file.seek(0)
  hash_object = hashlib.sha256(elf_file.read())
  print "elf header orig hash =",hash_object.hexdigest()
  phdr_offset = metadata['pg_start'] + 32 * hash_seg['num']
  #print "phdr_offset = 0x%x" % phdr_offset
  elf_file.seek(phdr_offset + 4*4)
  elf_file.write(struct.pack("I", hash_file_size))
  elf_file.seek(0)
  hash_object = hashlib.sha256(elf_file.read())
  print "elf header NEW  hash =",hash_object.hexdigest()
  elf_file.close()

  print "Patch:",hash_fn
  hash_file = open(hash_fn, 'r+b')
  update_sec_hash(hash_file, 0, elf_seg['num'], hash_object.digest())
  hash_file.close()

  print "Patch:",mdt_fn
  mdt_file = open(mdt_fn, 'r+b')
  hs_offset = metadata['pg_start'] + 32 * metadata['num_segments']
  update_sec_hash(mdt_file, hs_offset, elf_seg['num'], hash_object.digest())
  phdr_offset = metadata['pg_start'] + 32 * hash_seg['num']
  mdt_file.seek(phdr_offset + 4*4)
  mdt_file.write(struct.pack("I", hash_file_size))
  mdt_file.close()

if (options.upd_hash):
  print "---------- Update hash table -------------"
  
  for i, seg in enumerate(metadata['segments']):
    filesz = seg['filesz']
    #print "[" + "%02d" % i + "] stor_hash =","".join("{:02x}".format(ord(c)) for c in seg['stor_hash'])
    sec_fn = "./%s.b%02d" % (options.prefix, seg['num'])
    sec_exist = os.path.isfile(sec_fn)
    if (filesz > 0 and not sec_exist):
      die("Error: 001 %d" % filesz)
    if (not sec_exist):
      continue
    if (seg['stor_hash'] == '\0'*32):
      continue
    seg['real_hash'] = get_file_sha256(sec_fn)
    
    if (seg['stor_hash'] != seg['real_hash']):
      print "[" + "%02d" % i + "] stor_hash =","".join("{:02x}".format(ord(c)) for c in seg['stor_hash'])
      print "     real_hash =","".join("{:02x}".format(ord(c)) for c in seg['real_hash'])

      print "Patch:",hash_fn
      hash_file = open(hash_fn, 'r+b')
      update_sec_hash(hash_file, 0, seg['num'], seg['real_hash'])
      hash_file.close()

      print "Patch:",mdt_fn
      mdt_file = open(mdt_fn, 'r+b')
      hs_offset = metadata['pg_start'] + 32 * metadata['num_segments']
      update_sec_hash(mdt_file, hs_offset, seg['num'], seg['real_hash'])
      mdt_file.close()

