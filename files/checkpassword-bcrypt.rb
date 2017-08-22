#!/usr/bin/env ruby

require File.join(File.dirname(__FILE__), "checkpassword-bcrypt.incl.rb")

#if authorized is set to 1, dovecot does a userdb lookup. no login required.
authorized = ENV['AUTHORIZED'].to_i
dovecot = ARGV[0]
ip = ENV['TCPREMOTEIP']

begin
  input = IO.new(3,"r")
  (username,pass) = input.read.unpack("Z*Z*")
  input.close
rescue
  warn "could not read username/pass from stdin, terminating"
  exit InternalAuthError
end

def trusted_ip?(ip)
  CheckpasswordBCrypt::Config::TrustedIps.include?(ip)
end

trusted_login = trusted_ip?(ip)
if trusted_login && pass =~ /(.*)##untrusted_login$/ then
  pass = $1
  trusted_login = false
end

checker = CheckpasswordBCrypt::PasswordChecker.new

begin
  checker.prepare!

  # we do not want to fail on if we're just doing a userdb lookup
  fail_when_locked = (authorized != 1) && !trusted_login

  exit AuthError unless checker.user?(username, fail_when_locked)

  if authorized != 1
    exit AuthError unless checker.pass?(pass)
  end
rescue CheckpasswordBCrypt::InternalError
  warn "authentication not possible, terminating..."
  exit InternalAuthError
end

user = checker.user
# do not perform a full login if dovecot just does a userdb lookup
checker.login! unless authorized == 1

# cleanup checker
checker.finish

ENV['USER']              = user['name']
ENV['HOME']              = File.join(user['home'],user['name'])
extras = []
CheckpasswordBCrypt::Config::Dovecot::ExtraUserDBFields.keys.each do |key|
  script_key = "userdb_#{key}"
  val = CheckpasswordBCrypt::Config::Dovecot::ExtraUserDBFields[key]
  val = val.call(user) if val.is_a?(Proc)
  if val && (!val.respond_to?(:empty?) || !val.empty?)
    ENV[script_key] = val
    extras << script_key
  end
end
ENV['EXTRA']             = extras.join(' ')
ENV['AUTHORIZED']        = '2' if authorized == 1
# keep FD 4 open as dovecot communicates on that one
exec dovecot, { 4 => 4 }
