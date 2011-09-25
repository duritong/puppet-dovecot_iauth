class dovecot-iauth::base {
    require rubygems::activesupport
    require rubygems::postgres
    require rubygems::digest

    package { 'dovecot-iauth':
        ensure => present,
    }
}
