#!/usr/bin/env ruby

require 'rubygems'
require 'postgres'
require 'digest'
require 'bcrypt'

CONF_DIR = "/e/dovecot/bin/"

require File.join(CONF_DIR, "checkpassword-bcrypt.conf.rb")
require File.join(CONF_DIR, "checkpassword-bcrypt.sql.conf.rb")

InternalAuthError = 111
AuthError         = 1

module CheckpasswordBCrypt

  class PasswordChecker

    def initialize
      @connection = PGconn.connect(
         Config::DB::Host, 5432, "","",
         Config::DB::Database,
         Config::DB::User,
         Config::DB::Password)
    end

    def is_email( email )
      email_regex = %r{
        [0-9a-z] # First character
        [0-9a-z.\-_]* # Middle characters
        [0-9a-z]? # Last character
        @
        [0-9a-z] # Domain name begin
        [0-9a-z.\-]+ # Domain name middle
        [0-9a-z] # Domain name end
        $}xi
      if email =~ email_regex
        true
      else
        warn "not a 'valid' email address: #{email}"
        false
      end
    end

    def escape(string)
      PGconn.escape(string)
    end

    def get_user(username)
      return nil unless is_email( username )
      username = escape(username)
      sql = sprintf( Config::SQL::UserQuery, username )
      begin
	res = @connection.exec(sql)
      rescue PGError => e
        warn "sql failed with: #{e} (#{sql})"
        return nil
      end
      unless res[0]
        warn "got empty result for user #{username}"
        return nil
      end

      parse_user( res[0] )
    end

    def parse_user( user_rec )
      user = {}
      (user[:name],user[:hash],user[:uid],
       user[:quota],user[:lastlogin]) = user_rec
      user[:gid]  = Config::Mail::Gid
      user[:home] = Config::Mail::Home
      parse_hash( user )
    end

    def parse_hash( user )
      user[:hash] =~ /\{(.*)\}(.*)/
      user[:hash_algo] = $1
      user[:hash_raw] = $2
      if user[:hash_algo] == nil then
        Config::UnknownHashAlgo.call( user )
      end
      user
    end

    def bcrypt(pass)
        BCrypt::Password.create(pass,:cost=>Config::BCrypt::Cost)
    end

    def hash?(user, pass)
      if user[:hash_algo] == 'BCrypt'
      	result = BCrypt::Password.new(user[:hash_raw]) == pass
	      warn "aborting: bcrypt hashes do not match: #{user[:name]}" unless result
        begin
          warn "multibyte chars: #{pass.unpack("U*").size != pass.size}" unless result
        rescue
          warn "pw has no valid encoding"
        end
        return result
      end

      unless Config::Migration
        warn "aborting: no bcrypt hash for user #{user[:name]} and migration disabled"
        return false
      end

      #this is an old hash which needs migration
      return false unless old_hash(user,pass) == user[:hash_raw]
      migrate_hash(user,pass)
      true
    end

    def old_hash(user, pass)
      case user[:hash_algo]
        when 'CRYPT'
          salt = user[:hash_raw][0..1]
          pass.crypt(salt)
        when 'MD5'
          [Digest::MD5::digest(pass)].pack("m").gsub("\n", '')
        else
          warn "aborting: hash algo #{user[:hash_algo]} on user #{user[:name]} is not supported for migration"
          exit InternalAuthError
      end
    end

    def migrate_hash(user,pass)
      print "migrating #{user[:name]} to bcrypt"
      new_hash    = bcrypt(pass)

      if new_hash.empty?
        warn "generating hash for #{user[:name]} failed"
        return
      end
      sql = sprintf( Config::SQL::UserMigrate,
                     new_hash, user[:name])

      begin
	@connection.exec(sql)
      rescue PGError => e
        warn "sql failed with: #{e} (#{sql})"
      end
    end

    def login(user)
      current_time = Time.now.strftime('%Y%m')
      if Config::KeepLastLogin and user[:lastlogin] != current_time
        sql = sprintf( Config::SQL::UpdateLastLogin, current_time, user[:name] )
        begin
  	  @connection.exec(sql)
        rescue PGError => e
          warn "sql failed with: #{e} (#{sql})"
        end
      end
    end
  end
end
