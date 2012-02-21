#!/usr/bin/env ruby

require File.join(File.dirname(__FILE__), "checkpassword-bcrypt.incl.rb")

#if authorized is set to 1, dovecot does a userdb lookup. no login required.
authorized = ENV['AUTHORIZED']
dovecot = ARGV[0]

begin
  input = IO.new(3,"r")
  (username,pass) = input.read.unpack("Z*Z*")
  input.close
rescue
  warn "warning: could not read username/pass from stdin"
  exit AuthError
end

checker = CheckpasswordBCrypt::PasswordChecker.new

user = checker.get_user(username)
if user.nil? || user.empty?
  warn "warning: auth error #{user.inspect}, could not fetch user"
  exit AuthError
end

if( authorized != "1" )
  unless checker.hash?(user, pass)
    warn "warning: auth error #{user.inspect}, pw check failed"
    exit AuthError
  end
  checker.login( user )
end

new_env = "USER='#{user[:name]}' "+
          "HOME='#{user[:home]}#{user[:name]}' "+
          "EXTRA=\"userdb_uid userdb_gid userdb_quota_rule\" "+
          "userdb_quota_rule='#{user[:quota]}' "+
          "userdb_uid='#{user[:uid]}' "+
          "userdb_gid='#{user[:gid]}' "+
          (authorized == "1" ? "AUTHORIZED=2" : '')

exec "#{new_env} #{dovecot}"

