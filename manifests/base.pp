class dovecot-iauth::base {
    package { 'dovecot-iauth':
        ensure => absent,
    }

    include rubygems::bcrypt
    
    file{'/usr/libexec/dovecot/checkpassword-bcrypt/checkpassword-bcrypt.rb':
      source => "puppet:///modules/dovecot-iauth/checkpassword-bcrypt.rb",
      require => Package['dovecot'],
      before => Service['dovecot'],
      owner => root, group => root, mode => 0755;
    }
    file{'/usr/libexec/dovecot/checkpassword-bcrypt/checkpassword-bcrypt.incl.rb':
      source => "puppet:///modules/dovecot-iauth/checkpassword-bcrypt.incl.rb",
      require => Package['dovecot'],
      before => Service['dovecot'],
      owner => root, group => root, mode => 0755;
    }
}
