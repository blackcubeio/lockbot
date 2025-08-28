<?php

namespace blackcube\lockbot;

enum Algorithm: string
{
    case SHA1 = 'sha1';
    case SHA256 = 'sha256';
    case SHA384 = 'sha384';
    case SHA512 = 'sha512';
}