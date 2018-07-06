require 'ffi'

module Sodium
  module Lib
    extend FFI::Library

    ffi_lib '/usr/lib64/libsodium.so.23'

    attach_function :crypto_pwhash,
      [:pointer, :ulong_long, :pointer, :ulong_long, :pointer, :ulong_long, :size_t, :int], :int
    attach_function :crypto_pwhash_str,
      [:pointer, :pointer, :ulong_long, :ulong_long, :size_t], :int
    attach_function :crypto_pwhash_str_verify,
      [:pointer, :pointer, :ulong_long], :int
    attach_function :crypto_pwhash_str_needs_rehash,
      [:pointer, :ulong_long, :size_t], :int
    attach_function :crypto_box_keypair,
      [:pointer, :pointer], :int
    attach_function :crypto_box_easy,
      [:pointer, :pointer, :ulong_long, :pointer, :pointer, :pointer], :int
    attach_function :crypto_scalarmult_base,
      [:pointer, :pointer], :int
    attach_function :crypto_box_open_easy,
      [:pointer, :pointer, :ulong_long, :pointer, :pointer, :pointer], :int
    attach_function :randombytes_buf,
      [:pointer, :size_t], :int
    attach_function :crypto_secretbox_keygen,
      [:pointer], :int
    attach_function :crypto_secretbox_easy,
      [:pointer, :pointer, :ulong_long, :pointer, :pointer], :int
    attach_function :crypto_secretbox_open_easy,
      [:pointer, :pointer, :ulong_long, :pointer, :pointer], :int

    attach_function :sodium_init, [], :int

    attach_function :crypto_pwhash_argon2id_opslimit_min, [], :size_t
    attach_function :crypto_pwhash_argon2id_opslimit_max, [], :size_t
    attach_function :crypto_pwhash_argon2id_memlimit_min, [], :size_t
    attach_function :crypto_pwhash_argon2id_memlimit_max, [], :size_t

    attach_function :crypto_pwhash_argon2id_opslimit_interactive,  [], :size_t
    attach_function :crypto_pwhash_argon2id_memlimit_interactive,  [], :size_t
    attach_function :crypto_pwhash_argon2id_opslimit_moderate,     [], :size_t
    attach_function :crypto_pwhash_argon2id_memlimit_moderate,     [], :size_t
    attach_function :crypto_pwhash_argon2id_opslimit_sensitive,    [], :size_t
    attach_function :crypto_pwhash_argon2id_memlimit_sensitive,    [], :size_t

    attach_function :crypto_box_publickeybytes,      [], :size_t 
    attach_function :crypto_box_secretkeybytes,      [], :size_t 
    attach_function :crypto_box_macbytes,            [], :size_t 
    attach_function :crypto_box_noncebytes,          [], :size_t 

    attach_function :crypto_secretbox_keybytes,      [], :size_t 
    attach_function :crypto_secretbox_macbytes,      [], :size_t 
    attach_function :crypto_secretbox_noncebytes,    [], :size_t 

    attach_function :crypto_pwhash_saltbytes,    [], :size_t 
    attach_function :crypto_pwhash_strbytes,     [], :size_t 

    attach_function :crypto_pwhash_alg_argon2id13, [], :int
    attach_function :crypto_pwhash_alg_argon2i13,  [], :int
  end

  Lib::sodium_init() == 0 or throw :init_err

  module PwHash
    ALG_ARGON2ID13   = Lib::crypto_pwhash_alg_argon2id13()
    ALG_ARGON2I13    = Lib::crypto_pwhash_alg_argon2i13()
    DEFAULT_OPSLIMIT = Lib::crypto_pwhash_argon2id_opslimit_moderate()
    DEFAULT_MEMLIMIT = Lib::crypto_pwhash_argon2id_memlimit_moderate()
    HASH_SALT_BYTES  = Lib::crypto_pwhash_saltbytes()
    STR_HASH_BYTES   = Lib::crypto_pwhash_strbytes()

    def self.h(pw, opslimit = DEFAULT_OPSLIMIT, memlimit = DEFAULT_MEMLIMIT)
      buf = FFI::MemoryPointer.new(:uchar, STR_HASH_BYTES)
      r = Lib::crypto_pwhash_str(buf, pw, pw.length, opslimit, memlimit)
      throw :hash_err unless r == 0
      buf.read_string()
    end

    def self.check(pw, hash)
      Lib::crypto_pwhash_str_verify(hash, pw, pw.length) == 0
    end

    def self.rehash?(hash, opslimit = DEFAULT_OPSLIMIT, memlimit = DEFAULT_MEMLIMIT)
      Lib::crypto_pwhash_str_needs_rehash(hash, opslimit, memlimit) != 0
    end

    def self.kdf(pw, len, salt, opslimit, memlimit, algo = ALG_ARGON2ID13)
      buf = FFI::MemoryPointer.new(:uchar, len)
      r = Lib::crypto_pwhash(buf, len, pw, pw.length, salt, opslimit, memlimit, algo)
      throw :hash_key_err unless r == 0
      buf.get_bytes(0, len)
    end
  end

  module Box
    PUB_KEYBYTES = Lib::crypto_box_publickeybytes()
    SEC_KEYBYTES = Lib::crypto_box_secretkeybytes()
    MACBYTES     = Lib::crypto_box_macbytes()
    NONCEBYTES   = Lib::crypto_box_noncebytes()

    def self.gen_keypair()
      pub = FFI::MemoryPointer.new(:uchar, PUB_KEYBYTES)
      sec = FFI::MemoryPointer.new(:uchar, SEC_KEYBYTES)
      r = Lib::crypto_box_keypair(pub, sec);
      throw :gen_keypair_err unless r == 0
      {pub: pub.get_bytes(0, PUB_KEYBYTES),
       sec: sec.get_bytes(0, SEC_KEYBYTES)}
    end

    def self.pubkey(sec)
      buf = FFI::MemoryPointer.new(:uchar, PUB_KEYBYTES)
      r = Lib::crypto_scalarmult_base(buf, sec)
      throw :calc_pubkey_err unless r == 0
      return buf.get_bytes(0, PUB_KEYBYTES)
    end

    def self.close(pub, sec, data)
      bytes = data.length + MACBYTES
      buf = FFI::MemoryPointer.new(:uchar, bytes)
      nonce = Random::bytes(NONCEBYTES)
      r = Lib::crypto_box_easy(buf, data, data.length, nonce, pub, sec)
      throw :box_close_err unless r == 0
      nonce + buf.get_bytes(0, bytes)
    end

    def self.open(pub, sec, data, plain_length = nil)
      nonce = data[0...NONCEBYTES]
      data = data[NONCEBYTES...data.length]
      plain_length ||= data.length - MACBYTES
      buf = FFI::MemoryPointer.new(:uchar, plain_length)
      r = Lib::crypto_box_open_easy(buf, data, data.length, nonce, pub, sec)
      throw :box_open_err unless r == 0
      buf.get_bytes(0, plain_length)
    end
  end

  class SecretBox
    KEYBYTES   = Lib::crypto_secretbox_keybytes()
    MACBYTES   = Lib::crypto_secretbox_macbytes()
    NONCEBYTES = Lib::crypto_secretbox_noncebytes()

    attr_reader :data, :nonce, :salt, :opslimit, :memlimit

    def initialize(data, nonce, salt, opslimit, memlimit)
      @data = data
      @nonce = nonce
      @salt = salt
      @opslimit = opslimit
      @memlimit = memlimit
    end

    def self.close(pw, data)
      salt = Random::bytes(PwHash::HASH_SALT_BYTES)
      opslimit = PwHash::DEFAULT_OPSLIMIT
      memlimit = PwHash::DEFAULT_MEMLIMIT
      key = PwHash::kdf(pw, KEYBYTES, salt, opslimit, memlimit)
      box_bytes = MACBYTES + data.length
      buf = FFI::MemoryPointer.new(:uchar, box_bytes)
      nonce = Random::bytes(NONCEBYTES)
      r = Lib::crypto_secretbox_easy(buf, data, data.length, nonce, key)
      throw :secretbox_close_err unless r == 0
      SecretBox.new(
        buf.get_bytes(0, box_bytes),
        nonce,
        salt,
        opslimit,
        memlimit,)
    end

    def open(pw, expected_plain_size = nil)
      plain_size = data.size - MACBYTES
      if expected_plain_size && plain_size != expected_plain_size
        throw :wrong_size
      end
      key = PwHash::kdf(pw, KEYBYTES, salt, opslimit, memlimit)
      buf = FFI::MemoryPointer.new(:uchar, data.length)
      r = Lib::crypto_secretbox_open_easy(buf, data, data.length, nonce, key)
      throw :secretbox_open_err unless r == 0
      buf.get_bytes(0, plain_size)
    end
  end

  module Random
    def self.bytes(l)
      buf = FFI::MemoryPointer.new(:uchar, l)
      r = Lib::randombytes_buf(buf, l)
      throw :randombytes_err unless r == 0
      buf.get_bytes(0, l)
    end
  end
end


module Trees
  def self.to_hex(v)
    "#{v.unpack('H*')[0]}"
  end

  # creates a fresh public crypto keypair, stores it into a symmetric secretbox
  # and returns it in a format compatible with trees
  def self.create(pw)
    key = Sodium::Box::gen_keypair()
    box = Sodium::SecretBox::close(pw, key[:sec])
    [key[:pub], KeyBox::from_box(box)]
  end

  # unlocks the trees compatible secretbox and creates a recovery token for
  # the secret key that is in it
  def self.recovery(pw, box, account, recovery_master_pub, recovery_issuer_sec)
    secret = box.open_raw(pw)
    t = Sodium::Box::close(recovery_master_pub, recovery_issuer_sec, secret + account)
    [t].pack("m").sub("\n","")
  end

  # takes a recovery token, the master secret and a new passwort, then creates a
  # new trees compatible secretbox with the new passwort
  def self.recovery_open(recovery_box, recovery_issuer_pub, recovery_master_sec, new_pw)
    recovery_box = recovery_box.unpack("m")[0]
    recover = Sodium::Box::open(recovery_issuer_pub, recovery_master_sec, recovery_box)
    sec     = recover[0...Sodium::Box::SEC_KEYBYTES]
    account = recover[Sodium::Box::SEC_KEYBYTES...recover.length].sub(0.chr,'')
    new_box = Sodium::SecretBox::close(new_pw, sec)
    pub  = Sodium::Box::pubkey(sec)
    [account, pub, KeyBox::from_box(new_box)]
  end

  class KeyBox
    def self.to_hex(v)
      "#{v.unpack('H*')[0]}"
    end

    def from_hex(x)
      [x].pack('H*')
    end

    # Deserialize relies on fixed length fields. If libsodium changes those
    # sizes we need to parse by delimiter
    DATA_LEN  = 96
    NONCE_LEN = 48
    SALT_LEN  = 32

    attr_reader :data, :nonce, :salt, :opslimit, :memlimit, :box

    def initialize(data, nonce, salt, opslimit, memlimit)
      @data = data
      @nonce = nonce
      @salt = salt
      @opslimit = opslimit
      @memlimit = memlimit
      @box = Sodium::SecretBox.new(
        from_hex(data), from_hex(nonce), from_hex(salt), Integer(@opslimit), Integer(@memlimit))
    end

    def open_raw(pw)
      box.open(pw, Sodium::Box::SEC_KEYBYTES)
    end

    def open(pw)
      open_raw(pw).unpack('H*')[0]
    end

    def check_pw(pw)
      begin
        open_raw(pw)
      rescue
        return false
      end
      true
    end

    def serialize
      raise :wrong_payload_len unless data.length == DATA_LEN
      raise :wrong_nonce_len unless nonce.length == NONCE_LEN
      raise :wrong_salt_len unless salt.length == SALT_LEN
      "#{data}$#{nonce}$#{salt}$#{opslimit}$#{memlimit}"
    end

    def to_s
      serialize
    end

    def self.deserialize(str)
      data = str[0...DATA_LEN]
      pos = DATA_LEN+1
      nonce = str[pos...(pos+NONCE_LEN)]
      pos += NONCE_LEN+1
      salt = str[pos...(pos+SALT_LEN)]
      pos += SALT_LEN+1
      rest = str[pos..-1]
      (opslimit, memlimit) = rest.split("$")
      KeyBox.new(data, nonce, salt, opslimit, memlimit)
    end

    def self.from_box(box)
      KeyBox.new(to_hex(box.data), to_hex(box.nonce), to_hex(box.salt),
                 box.opslimit, box.memlimit)
    end
  end

  def self.authenticate(pw, serialized_box, serialized_extra_boxes)
    b = KeyBox::deserialize(serialized_box)
    if (b.check_pw(pw))
      return b
    end
    if serialized_extra_boxes && !serialized_extra_boxes.empty?
      serialized_extra_boxes.split(",").each do |serialized_extra_box|
        eb = KeyBox::deserialize(serialized_extra_box)
        if (eb.check_pw(pw))
          return eb
        end
      end
    end
    false
  end
end
