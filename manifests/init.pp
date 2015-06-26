# module to manage dovecot iauth
class dovecot_iauth {
  include rubygems::bcrypt

  file{
    '/usr/libexec/dovecot/checkpassword-bcrypt' :
      ensure  => directory,
      require => Package['dovecot'],
      owner   => root,
      group   => root,
      mode    => '0644';
    '/usr/libexec/dovecot/checkpassword-bcrypt/checkpassword-bcrypt.rb':
      source  => 'puppet:///modules/dovecot_iauth/checkpassword-bcrypt.rb',
      before  => Service['dovecot'],
      owner   => root,
      group   => root,
      mode    => '0755';
    '/usr/libexec/dovecot/checkpassword-bcrypt/checkpassword-bcrypt.incl.rb':
      source  => 'puppet:///modules/dovecot_iauth/checkpassword-bcrypt.incl.rb',
      before  => Service['dovecot'],
      owner   => root,
      group   => root,
      mode    => '0755';
  }
}
