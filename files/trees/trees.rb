def to_hex(v)
  "#{v.unpack('H*')[0]}"
end

def from_hex(x)
  [x].pack('H*')
end

def char_array(len)
  Fiddle::Pointer.malloc(len * Fiddle::SIZEOF_CHAR)
end

module Trees
  module Sodium
    require 'fiddle'

    module Lib
      # written agains libsodium 1.0.15

      LIB_SODIUM = Fiddle.dlopen('/usr/lib64/libsodium.so.23')
      def self.extern_(name, ret, args = [])
        arg_names = (0...(args.size)).map{|a| "arg_#{a}"}.join(',')
        fun_handle = "EXTERN_#{name.upcase}"
        class_eval (
          "#{fun_handle} = Fiddle::Function.new(LIB_SODIUM['#{name}'], #{args}, #{ret})
           def self.#{name} (#{arg_names})
             #{fun_handle}.call(#{arg_names})
           end")
      end

      INT       = Fiddle::TYPE_INT
      CHARP     = Fiddle::TYPE_VOIDP
      VOID      = Fiddle::TYPE_VOID
      LONG_LONG = Fiddle::TYPE_LONG_LONG
      SIZE_T    = Fiddle::TYPE_SIZE_T


      # int sodium_init()
      extern_ 'sodium_init', INT


      # pwhash

      # int crypto_pwhash(unsigned char * const out, unsigned long long outlen,
      #        const char * const passwd, unsigned long long passwdlen,
      #        const unsigned char * const salt,
      #        unsigned long long opslimit, size_t memlimit, int alg)'
      extern_ 'crypto_pwhash', INT,
        [CHARP, LONG_LONG, CHARP, LONG_LONG, CHARP, LONG_LONG, SIZE_T, INT]


      # box

      # int crypto_box_keypair(unsigned char *pk, unsigned char *sk)
      extern_ 'crypto_box_keypair', INT, [CHARP, CHARP]

      # int crypto_box_easy(unsigned char *c, const unsigned char *m,
      #      unsigned long long mlen, const unsigned char *n,
      #      const unsigned char *pk, const unsigned char *sk)'
      extern_ 'crypto_box_easy', INT,
        [CHARP, CHARP, LONG_LONG, CHARP, CHARP, CHARP]

      # int crypto_box_open_easy(unsigned char *m, const unsigned char *c,
      #      unsigned long long clen, const unsigned char *n,
      #      const unsigned char *pk, const unsigned char *sk)'
      extern_ 'crypto_box_open_easy', INT,
        [CHARP, CHARP, LONG_LONG, CHARP, CHARP, CHARP]


      # scalarmult

      # int crypto_scalarmult_base(unsigned char *q, const unsigned char *n)
      extern_ 'crypto_scalarmult_base', INT, [CHARP, CHARP]


      # randombytes

      # void randombytes_buf(const void * buf, size_t size)
      extern_ 'randombytes_buf', VOID, [CHARP, SIZE_T]


      # secretbox

      # int crypto_secretbox_easy(unsigned char *c, const unsigned char *m,
      #         unsigned long long mlen, const unsigned char *n,
      #         const unsigned char *k)'
      extern_ 'crypto_secretbox_easy', INT,
        [CHARP, CHARP, LONG_LONG, CHARP, CHARP]

      # int crypto_secretbox_open_easy(unsigned char *m, const unsigned char *c,
      #         unsigned long long clen, const unsigned char *n,
      #         const unsigned char *k)'
      extern_ 'crypto_secretbox_open_easy', INT,
        [CHARP, CHARP, LONG_LONG, CHARP, CHARP]

      # consts
      extern_ 'crypto_pwhash_alg_argon2i13', INT
      extern_ 'crypto_pwhash_alg_argon2id13', INT

      extern_ 'crypto_pwhash_saltbytes', SIZE_T
      extern_ 'crypto_pwhash_strbytes', SIZE_T

      extern_ 'crypto_pwhash_opslimit_interactive', SIZE_T
      extern_ 'crypto_pwhash_memlimit_interactive', SIZE_T
      extern_ 'crypto_pwhash_opslimit_moderate', SIZE_T
      extern_ 'crypto_pwhash_memlimit_moderate', SIZE_T
      extern_ 'crypto_pwhash_opslimit_sensitive', SIZE_T
      extern_ 'crypto_pwhash_memlimit_sensitive', SIZE_T

      extern_ 'crypto_box_publickeybytes', SIZE_T
      extern_ 'crypto_box_secretkeybytes', SIZE_T
      extern_ 'crypto_box_macbytes', SIZE_T
      extern_ 'crypto_box_noncebytes', SIZE_T

      extern_ 'crypto_secretbox_keybytes', SIZE_T
      extern_ 'crypto_secretbox_macbytes', SIZE_T
      extern_ 'crypto_secretbox_noncebytes', SIZE_T
    end

    Lib::sodium_init() == 0 or throw :init_err


    module PwHash
      ALG_ARGON2ID13 = Lib::crypto_pwhash_alg_argon2id13()
      SALTBYTES      = Lib::crypto_pwhash_saltbytes()

      def self.kdf(pw, len, salt, opslimit, memlimit, algo = ALG_ARGON2ID13)
        buf = char_array(len)
        r = Lib::crypto_pwhash(buf, len, pw, pw.length, salt, opslimit, memlimit, algo)
        throw :hash_key_err unless r == 0
        buf.to_str
      end
    end

    module Box
      PUB_KEYBYTES = Lib::crypto_box_publickeybytes()
      SEC_KEYBYTES = Lib::crypto_box_secretkeybytes()
      MACBYTES     = Lib::crypto_box_macbytes()
      NONCEBYTES   = Lib::crypto_box_noncebytes()

      def self.gen_keypair()
        pub = char_array(PUB_KEYBYTES)
        sec = char_array(SEC_KEYBYTES)
        r = Lib::crypto_box_keypair(pub, sec);
        throw :gen_keypair_err unless r == 0
        [pub.to_str, sec.to_str]
      end

      def self.pubkey(sec)
        buf = char_array(PUB_KEYBYTES)
        r = Lib::crypto_scalarmult_base(buf, sec)
        throw :calc_pubkey_err unless r == 0
        return buf.to_str
      end

      def self.close(pub, sec, data)
        bytes = data.length + MACBYTES
        buf = char_array(bytes)
        nonce = Random::bytes(NONCEBYTES)
        r = Lib::crypto_box_easy(buf, data, data.length, nonce, pub, sec)
        throw :box_close_err unless r == 0
        nonce + buf.to_str
      end

      def self.open(pub, sec, data, plain_length = nil)
        nonce = data[0...NONCEBYTES]
        data = data[NONCEBYTES...data.length]
        plain_length ||= data.length - MACBYTES
        buf = char_array(plain_length)
        r = Lib::crypto_box_open_easy(buf, data, data.length, nonce, pub, sec)
        throw :box_open_err unless r == 0
        buf.to_str(plain_length)
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

      def self.close(pw, data, opslimit, memlimit)
        salt = Random::bytes(PwHash::SALTBYTES)
        key = PwHash::kdf(pw, KEYBYTES, salt, opslimit, memlimit)
        box_bytes = MACBYTES + data.length
        buf = char_array(box_bytes)
        nonce = Random::bytes(NONCEBYTES)
        r = Lib::crypto_secretbox_easy(buf, data, data.length, nonce, key)
        throw :secretbox_close_err unless r == 0
        SecretBox.new(
          buf.to_str,
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
        buf = char_array(data.length)
        r = Lib::crypto_secretbox_open_easy(buf, data, data.length, nonce, key)
        throw :secretbox_open_err unless r == 0
        buf.to_str(plain_size)
      end
    end

    module Random
      def self.bytes(l)
        buf = char_array(l)
        Lib::randombytes_buf(buf, l)
        buf.to_str
      end
    end
  end

  DEFAULT_PWHASH_OPSLIMIT = Sodium::Lib::crypto_pwhash_opslimit_sensitive
  DEFAULT_PWHASH_MEMLIMIT = Sodium::Lib::crypto_pwhash_memlimit_interactive

  # This class provides the glue code between a generic sodium secretbox
  # and a secret box with all metadata and serialization format that we
  # use for trees
  class KeyBox
    # A trees keybox data part consists of a sodium Box secret key and the
    #   sodium box mac (times 2 since it is hexstring)
    DATA_LEN  = (Sodium::Box::SEC_KEYBYTES + Sodium::SecretBox::MACBYTES)*2
    NONCE_LEN = Sodium::SecretBox::NONCEBYTES*2
    SALT_LEN  = Sodium::PwHash::SALTBYTES*2

    # Deserialize relies on fixed length fields. If libsodium changes those
    # sizes we need to parse by delimiter
    throw :sodium_api_change unless DATA_LEN  == 96
    throw :sodium_api_change unless NONCE_LEN == 48
    throw :sodium_api_change unless SALT_LEN  == 32

    attr_reader :data, :nonce, :salt, :opslimit, :memlimit

    def initialize(data, nonce, salt, opslimit, memlimit)
      @data = data
      @nonce = nonce
      @salt = salt
      @opslimit = opslimit
      @memlimit = memlimit
      @box = Sodium::SecretBox.new(
        from_hex(data), from_hex(nonce), from_hex(salt),
        Integer(@opslimit), Integer(@memlimit))
    end

    def raw_data
      box.data
    end

    def open_raw(pw)
      @box.open(pw, Sodium::Box::SEC_KEYBYTES)
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
      "#{data}:#{nonce}:#{salt}:#{opslimit}:#{memlimit}"
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
      (opslimit, memlimit) = rest.split(':')
      KeyBox.new(data, nonce, salt, opslimit, memlimit)
    end

    def self.from_box(box)
      KeyBox.new(to_hex(box.data), to_hex(box.nonce), to_hex(box.salt),
                 box.opslimit, box.memlimit)
    end
  end

  class KeyPair
    attr_reader :pub, :sec

    def initialize(pub, sec)
      @pub = pub
      @sec = sec
    end

    def self.create
      KeyPair.new(*Sodium::Box::gen_keypair())
    end
  end

  class KeyRing
    attr_reader :mine, :theirs

    def initialize(mine_sec, theirs_pub)
      @mine = mine_sec
      @theirs = theirs_pub
    end

    def serialize
      ys = theirs.map{|k| to_hex(k)}.join(":")
      "#{to_hex(mine)}:#{ys}"
    end

    def self.deserialize(str)
      inp = str.split(":")
      mine = from_hex(inp.shift)
      theirs = inp.map{|v| from_hex(v)}
      KeyRing.new(mine, theirs)
    end
  end

  # creates a fresh public crypto keypair, stores it into a symmetric secretbox
  # and returns it in a format compatible with trees
  def self.create(pw, opslimit = DEFAULT_PWHASH_OPSLIMIT,
                      memlimit = DEFAULT_PWHASH_MEMLIMIT)
    key = Sodium::Box::gen_keypair()
    box = Sodium::SecretBox::close(pw, key[1], opslimit, memlimit)
    [key[0], KeyBox::from_box(box)]
  end

  # changes the password
  def self.passwd(pw, new_pw, serialized_box,
                  opslimit = DEFAULT_PWHASH_OPSLIMIT,
                  memlimit = DEFAULT_PWHASH_MEMLIMIT)
    box = KeyBox::deserialize(serialized_box)
    key = box.open_raw(pw)
    new_box = Sodium::SecretBox::close(new_pw, key, opslimit, memlimit)
    KeyBox::from_box(new_box)
  end

  # create a temp password
  def self.duplicate_box(box)
    temp_pw = Sodium::Random::bytes(64)
    temp_pw = [temp_pw].pack("m").gsub("\n","")
    new_box = Sodium::SecretBox::close(
      temp_pw, box.raw_data, box.opslimit, box.memlimit)
    [temp_pw, KeyBox::from_box(new_box)]
  end


  # unlocks the trees compatible secretbox and creates a recovery token for
  # the secret key that is in it
  def self.recovery(pw, box, account, keyring)
    secret = box.open_raw(pw)
    # The issuer keyring needs exactly one target public key of the master
    throw :ambiguous_master if keyring.theirs.size != 1
    t = Sodium::Box::close(keyring.theirs[0], keyring.mine, secret + account)
    [t].pack("m").gsub("\n","")
  end

  def self.recovery_try_open(recovery_box, keyring)
    recovery_box = recovery_box.unpack("m")[0]
    keyring.theirs.each do |issuer_sign|
      begin
        return Sodium::Box::open(issuer_sign, keyring.mine, recovery_box)
      end
    end
  end

  # takes a recovery token, the master secret and a new passwort, then creates a
  # new trees compatible secretbox with the new passwort
  def self.recovery_open(recovery_box, keyring, new_pw,
                         opslimit = DEFAULT_PWHASH_OPSLIMIT,
                         memlimit = DEFAULT_PWHASH_MEMLIMIT)
    recover = recovery_try_open(recovery_box, keyring)
    sec     = recover[0...Sodium::Box::SEC_KEYBYTES]
    account = recover[Sodium::Box::SEC_KEYBYTES...recover.length].sub(0.chr,'')
    new_box = Sodium::SecretBox::close(new_pw, sec, opslimit, memlimit)
    pub  = Sodium::Box::pubkey(sec)
    [account, pub, KeyBox::from_box(new_box)]
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
