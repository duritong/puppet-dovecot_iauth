#!/usr/bin/env ruby

require 'rubygems'
require 'postgres'
require 'digest'
require 'bcrypt'
require 'base64'
require 'iconv'

CONF_DIR = "/e/dovecot/bin/"

require File.join(CONF_DIR, "checkpassword-bcrypt.conf.rb")
require File.join(CONF_DIR, "checkpassword-bcrypt.sql.conf.rb")

InternalAuthError = 111
AuthError         = 1

module CheckpasswordBCrypt

  class InternalError < Exception
  end

  class PasswordChecker

    attr_reader :user, :connection

    def prepare!
      begin 
        @connection = PGconn.connect(
           Config::DB::Host, 5432, "","",
           Config::DB::Database,
           Config::DB::User,
           Config::DB::Password)
      rescue PGError => e
        warn "could not connect to database: #{e}"
        raise InternalError
      end
    end

    def debug( str )
      warn str if Config::Debug
    end

    def email?( email )
      email_regex = %r{^
        [0-9a-z.!\#$%&'*+\-/=?^_`{|}~]+
        @
        [0-9a-z]
        [0-9a-z.\-]+
        [0-9a-z]
        $}xi
      if email =~ email_regex
        true
      else
        debug "#{email} is not a valid email address"
        false
      end
    end

    def escape(string)
      PGconn.escape(string)
    end
    
    def execute_sql(sql, *args)
      sql = sprintf( sql, *args.collect{ |a| escape("#{a}") } )
      begin
	connection.exec(sql)
      rescue PGError => e
        warn "sql failed with: #{e} (#{sql})"
        yield if block_given?
      end
    end 

    def fix_encoding(str)
      # stupid dovecot gives us latin or utf-8 chars
      # we fix this by assuming all illegal utf-8 strings are in fact latin
      begin
        str.unpack("U*")
      rescue
        return Iconv.conv('utf-8', 'iso-8859-1', str)
      end
      str
    end 

    def user?(username)
      return false unless email?( username )
      res = execute_sql( Config::SQL::UserQuery, username ) { return false }
      if res[0]
        @user = read_user( res[0] )
        ! locked?
      else
        debug "user #{username} does not exist"
        false
      end
    end

    def locked?
      return false unless Config::CheckAuthFailures
      return false if "#{user[:locked]}".empty?
      locked   = DateTime.parse(user[:locked])
      if DateTime.now < locked
        warn "user #{user[:name]} is locked until #{locked}"
        true
      else
        false
      end
    end

    def read_user( user_rec )
      user = {}
      (user[:name],user[:hash],user[:uid],
       user[:quota],user[:lastlogin],
       user[:auth_failures],user[:locked]) = user_rec
      user[:auth_failures] = user[:auth_failures].to_i
      user[:gid]  = Config::Mail::Gid
      user[:home] = Config::Mail::Home
      read_hash( user )
    end

    def read_hash( user )
      user[:hash] =~ /\{(.*)\}(.*)/
      user[:hash_algo] = $1
      user[:hash_raw] = $2
      if user[:hash_algo] == nil then
        Config::UnknownHashAlgo.call( user )
      end
      user
    end

    def encode_pass(pass)
      Base64.encode64(pass).chomp
    end
    
    def bcrypt(pass)
      BCrypt::Password.create(encode_pass(pass),:cost=>Config::BCrypt::Cost)
    end

    def lossy_hash(pass)
      # this hash is constructed so it does not allow an attacker to recover the original password:
      # only every second character is used and only a small part of the hash is returned.
      # but this should be enough to allow us to distinguish frequent logins with the same 
      # (but wrong) password from bruteforce attacks, where the password changes on every login.
      hash = []
      pick = pass.size % 2
      i    = pick+1
      hash << pass[0] << pass[-1]
      pass.each_char do |e|
        hash << e if i%2 == pick
        i += 1
      end
      hash = Digest::SHA512::digest(hash.sort.join)
      Base64.encode64(Digest::SHA512::digest(hash,user[:hash])[0..8]).chomp
    end

    def login_failed?(pass, raw_pass, hash)
      #old passwords can be either latin or utf-8 (now default) encoded...
      if user[:lastlogin][0..3].to_i <= 2012 && user[:lastlogin][4..5].to_i <= 3 && 
            (hash == pass || hash == raw_pass)
        debug "#{user[:name]} has an old non base64 encoded hash"
        migrate_hash(pass)
        return true
      end

      debug "password does not match BCrypt hash for #{user[:name]}"

      if Config::CheckAuthFailures
        auth_failures = user[:auth_failures] + 1
        if auth_failures >= Config::AuthFailuresLimit
          factor = 1 + auth_failures - Config::AuthFailuresLimit
          locked = DateTime.now + (factor * Config::LockTime / 1440.0)
        end
        execute_sql( Config::SQL::UpdateLoginFailure, auth_failures, locked || '', user[:name])
        debug "#{user[:name]} has #{auth_failures} auth failures. pw hash: #{lossy_hash(pass)}"
      end

      false
    end

    def pass?(raw_pass)
      pass = fix_encoding(raw_pass)
      if user[:hash_algo] == 'BCrypt'
      	hash = BCrypt::Password.new(user[:hash_raw])
        return hash == encode_pass(pass) || login_failed?(pass, raw_pass, hash)
      end

      unless Config::Migration
        warn "No bcrypt hash for user #{user[:name]} and migration disabled"
        raise InternalError
      end

      #this is an old hash which needs migration
      if old_hash(pass) == user[:hash_raw]
        migrate_hash(pass)
        true
      else
        debug "password does not match legacy hash for #{user[:name]}"
        false
      end
    end

    def old_hash(pass)
      case user[:hash_algo]
        when 'CRYPT'
          salt = user[:hash_raw][0..1]
          pass.crypt(salt)
        when 'MD5'
          Base64.encode64(Digest::MD5::digest(pass)).chomp
        else
          warn "hash algo #{user[:hash_algo]} at user #{user[:name]} is not supported for migration"
          raise InternalError
      end
    end

    def migrate_hash(pass)
      debug "migrating #{user[:name]} from #{user[:hash_algo]} to BCrypt"
      new_hash    = bcrypt(pass)
      if new_hash.empty?
        debug "generating hash for #{user[:name]} failed"
      else
        execute_sql( Config::SQL::UserMigrate, new_hash, user[:name] )
      end
    end

    def login!
      if Config::KeepLastLogin 
        current_time = Time.now.strftime('%Y%m')
        if user[:lastlogin] != current_time
          execute_sql( Config::SQL::UpdateLastLogin, current_time, user[:name] )
        end
      end
      if Config::CheckAuthFailures && user[:auth_failures] != 0
        execute_sql( Config::SQL::UpdateLoginFailure, 0, '', user[:name] )
        debug "#{user[:name]} auth failures (#{user[:auth_failures]}) reset"
      end
      connection.finish
    end
  end
end
