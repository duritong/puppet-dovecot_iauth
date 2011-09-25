class dovecot-iauth::base {
    require rubygems::activesupport
    require rubygems::postgres

    package { 'dovecot-iauth':
        ensure => present,
    }
}
