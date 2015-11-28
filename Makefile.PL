use 5.006;
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Crypt::DRBG',
    AUTHOR           => q{brian m. carlson <sandals@crustytoothpaste.net>},
    VERSION_FROM     => 'lib/Crypt/DRBG.pm',
    ABSTRACT_FROM    => 'lib/Crypt/DRBG.pm',
    LICENSE          => 'mit',
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.006,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
    },
    PREREQ_PM => {
        #'ABC'              => 1.6,
        #'Foo::Bar::Module' => 5.0401,
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Crypt-DRBG-*' },
);
