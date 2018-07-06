#!/usr/bin/env ruby

require 'rubygems'
require 'pg'
require 'digest'
require 'bcrypt'
require 'base64'
require 'iconv'
require 'date'

CONF_DIR = '/usr/libexec/dovecot/checkpassword-bcrypt'

require File.join(CONF_DIR, "checkpassword-bcrypt.conf.rb")
require File.join(CONF_DIR, "checkpassword-bcrypt.sql.conf.rb")

InternalAuthError = 111
AuthError         = 1

module Checkpassword

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

    def user?(username, fail_on_locked = true)
      return false unless email?( username )
      res = execute_sql( Config::SQL::UserQuery, username ) { return false }
      if res[0]
        @user = read_user( res[0] )
        if locked?
          debug "lookup of locked user #{username}"
          return !fail_on_locked
        end
        true
      else
        debug "user #{username} does not exist"
        false
      end
    end

    def locked?
      return false unless Config::CheckAuthFailures
      return false if "#{user['locked']}".empty?
      locked   = DateTime.parse(user['locked'])
      if DateTime.now < locked
        warn "user #{user['name']} is locked until #{locked}"
        true
      else
        false
      end
    end

    def read_user( user_rec )
      user = user_rec
      user['auth_failures'] = user['auth_failures'].to_i
      user['gid']  = Config::Mail::Gid
      user['home'] = Config::Mail::Home
      if user['trees_public_key'].to_s.empty?
        read_hash( user )
      else
        read_trees( user )
      end
    end

    def read_hash( user )
      user['hash'] =~ /\{(.*)\}(.*)/
      user['hash_algo'] = $1
      user['hash_raw'] = $2
      if user['hash_algo'] == nil then
        Config::UnknownHashAlgo.call( user )
      end
      user
    end

    def read_trees( user )
      user['trees_enabled'] = '1'
      user['trees_version'] = '1'
      user
    end

    def encode_pass(pass)
      Base64.strict_encode64(pass)
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
      hash << pass[0] << pass[-1]
      (1...pass.size).each do |i|
        hash << pass[i] if i%2 == pick
        i += 1
      end
      hash = Digest::SHA512::digest(hash.compact.sort.join)
      Base64.encode64(Digest::SHA512::digest("#{hash}#{pass.size}#{user['hash']}")[0..8]).chomp
    end

    def login_failed?(pass, raw_pass, hash)
      #old passwords can be either latin or utf-8 (now default) encoded...
      if user['lastlogin'][0..3].to_i <= 2012 && user['lastlogin'][4..5].to_i <= 3 && 
            (hash == pass || hash == raw_pass)
        debug "#{user['name']} has an old non base64 encoded hash"
        migrate_hash(pass)
        return true
      end

      if Config::CheckAuthFailures
        auth_failures = user['auth_failures'] + 1
        locked_until = nil
        if auth_failures >= Config::AuthFailuresLimit
          factor = 1 + auth_failures - Config::AuthFailuresLimit
          locked_for = [factor * Config::LockTime, Config::MaxLockTime].min
          locked_until = DateTime.now + locked_for / 1440.0
          warn "#{user['name']} is now locked. pw hash: #{lossy_hash(pass)}"
        end
        execute_sql( Config::SQL::UpdateLoginFailure, auth_failures, locked_until || '', user['name'])
      end

      debug "password does not match BCrypt hash for #{user['name']}. #{auth_failures}"

      false
    end

    def pass?(raw_pass)
      pass = fix_encoding(raw_pass)
      if user['trees_enabled'] == '1'
        require '/usr/local/trees/trees.rb'
        if box = Trees::authenticate(pass, user['trees_secret_box'], user['trees_extra_secret_boxes'])
          user['trees_password'] = pass
          user['trees_locked_secretbox'] = box.data
          user['trees_sk_nonce'] = box.nonce
          user['trees_pwhash_salt'] = box.salt
          user['trees_pwhash_opslimit'] = box.opslimit
          user['trees_pwhash_memlimit'] = box.memlimit
          return true
        else
          return false
        end
      else
        if user['hash_algo'] == 'BCrypt'
          hash = BCrypt::Password.new(user['hash_raw'])
          return hash == encode_pass(pass) || login_failed?(pass, raw_pass, hash)
        end

        unless Config::Migration
          warn "No bcrypt hash for user #{user['name']} and migration disabled"
          raise InternalError
        end

        #this is an old hash which needs migration
        if old_hash(pass) == user['hash_raw']
          migrate_hash(pass)
          true
        else
          debug "password does not match legacy hash for #{user['name']}"
          false
        end
      end
    end

    def old_hash(pass)
      case user['hash_algo']
        when 'CRYPT'
          salt = user['hash_raw'][0..1]
          pass.crypt(salt)
        when 'MD5'
          Base64.encode64(Digest::MD5::digest(pass)).chomp
        else
          warn "hash algo #{user['hash_algo']} at user #{user['name']} is not supported for migration"
          raise InternalError
      end
    end

    def migrate_hash(pass)
      debug "migrating #{user['name']} from #{user['hash_algo']} to BCrypt"
      new_hash    = bcrypt(pass)
      if new_hash.empty?
        debug "generating hash for #{user['name']} failed"
      else
        execute_sql( Config::SQL::UserMigrate, new_hash, user['name'] )
      end
    end

    def login!
      if Config::KeepLastLogin 
        current_time = Time.now.strftime('%Y%m')
        if user['lastlogin'] != current_time
          execute_sql( Config::SQL::UpdateLastLogin, current_time, user['name'] )
        end
      end
      if Config::CheckAuthFailures && user['auth_failures'] != 0
        execute_sql( Config::SQL::UpdateLoginFailure, 0, '', user['name'] )
        debug "#{user['name']} auth failures (#{user['auth_failures']}) reset"
      end
    end
    def finish
      connection.finish
    rescue PGError => e
      debug "Error while finishing: #{e}"
    end
  end
end
