#!/usr/bin/env ruby

require File.join(File.dirname(__FILE__), "checkpassword-bcrypt.incl.rb")

#if authorized is set to 1, dovecot does a userdb lookup. no login required.
authorized = ENV['AUTHORIZED'].to_i
dovecot = ARGV[0]

begin
  input = IO.new(3,"r")
  (username,pass) = input.read.unpack("Z*Z*")
  input.close
rescue
  warn "could not read username/pass from stdin, terminating"
  exit InternalAuthError
end

checker = CheckpasswordBCrypt::PasswordChecker.new

begin
  checker.prepare!

  unless checker.user?(username)
    exit AuthError
  end

  if authorized != 1
    unless checker.pass?(pass)
      exit AuthError
    end
  end
rescue CheckpasswordBCrypt::InternalError
  warn "authentication not possible, terminating..."
  exit InternalAuthError
end

user = checker.user
checker.login!

new_env = "USER='#{user[:name]}' "+
          "HOME='#{user[:home]}#{user[:name]}' "+
          "EXTRA=\"userdb_uid userdb_gid userdb_quota_rule\" "+
          "userdb_quota_rule='#{user[:quota]}' "+
          "userdb_uid='#{user[:uid]}' "+
          "userdb_gid='#{user[:gid]}' "+
          (authorized == "1" ? "AUTHORIZED=2" : '')

exec "#{new_env} #{dovecot}"

