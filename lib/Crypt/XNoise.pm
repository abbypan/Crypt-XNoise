#ABSTRACT: XNoise protocol
package Crypt::XNoise;

use strict;
use warnings;

use bignum;

require Exporter;

use Crypt::OpenSSL::EC;
use Crypt::OpenSSL::Bignum;

#use Crypt::OpenSSL::Hash2Curve;
use Crypt::OpenSSL::Base::Func;

use Storable qw(dclone);
use Digest::HMAC qw(hmac);
use Crypt::KeyDerivation ':all';
use Carp;

#use Smart::Comments;

our @ISA    = qw(Exporter);
our @EXPORT = qw/
  get_pattern_by_name
  noise_hkdf
  init_symmetric_state
  mix_key
  mix_hash
  init_key
  has_key
  rekey
  mix_keyandhash
  noise_split
  init_ciphersuite_name
  init_handshake_pattern
  init_protocol_name
  new_handshake_state
  encrypt_with_ad
  decrypt_with_ad
  encrypt_and_hash
  decrypt_and_hash
  derive_session_key_iv
  session_encrypt
  session_decrypt
  write_message
  read_message
  /;

our @EXPORT_OK = @EXPORT;

our %HANDSHAKE_PATTEN = (
    "N-N'" => {
        responder_pre_messages => [qw/s m/],
        messages               => [
            [qw/e es em/],
        ],
    },

    "K-K'" => {
        initiator_pre_messages => [qw/s m/], 
        responder_pre_messages => [qw/s m/],
        messages               => [
            [qw/e es ms em sm/],
        ],
    },

    "X-X'" => {
        responder_pre_messages => [qw/s m/],
        messages               => [
            [qw/e es em s m ms sm/],
        ],
    },

    "NK-N'K'" => {
        responder_pre_messages => [qw/s m/],
        messages               => [
            [qw/e es em/],
            [qw/e ee/],
        ],
    },

    "KK-K'K'" => {
        initiator_pre_messages => [qw/s m/], 
        responder_pre_messages => [qw/s m/],
        messages               => [
            [qw/e es em/],
            [qw/e ee se me/],
        ],
    },

    "IK-I'K'" => {
        responder_pre_messages => [qw/s m/],
        messages               => [
            [qw/e es em s m/],
            [qw/e ee se me/],
        ],
    },

    "N-X'" => {
        responder_pre_messages => [qw/s m/],
        messages               => [
            [qw/e es em m ms/],
        ],
    },

    "IX-I'X'" => {
        messages               => [
            [qw/e s m/],
            [qw/e ee se me s m es em/],
        ],
    },

    "NX-N'X'" => {
        messages               => [
            [qw/e/],
            [qw/e ee s m es em/],
        ],
    },

    "NK-X'K'" => {
        responder_pre_messages => [qw/s m/],
        messages               => [
            [qw/e es em/],
            [qw/e ee/],
            [qw/m me/],
        ],
    },

    "NX-X'X'" => {
        messages               => [
            [qw/e/],
            [qw/e ee s m es em/],
            [qw/m me/],
        ],
    },

    "XK-X'K'" => {
        responder_pre_messages => [qw/s m/],
        messages               => [
            [qw/e es em/],
            [qw/e ee/],
            [qw/s m se me/],
        ],
    },

    "NK1-N'K'1" => {
        responder_pre_messages => [qw/s m/],
        messages               => [
            [qw/e/],
            [qw/e ee es em/],
        ],
    },

    "XX-X'X'" => {
        messages               => [
            [qw/e/],
            [qw/e ee s m es em/],
            [qw/s m se me/],
        ],
    },

    "XX1-X'X'1" => {
        messages               => [
            [qw/e/],
            [qw/e ee s m/],
            [qw/es em s m se me/],
        ],
    },
);


sub get_pattern_by_name {
  my ( $pattern_name ) = @_;
  my $pattern = dclone( $HANDSHAKE_PATTEN{$pattern_name} );
  return $pattern;
}

sub noise_hkdf {
  my ( $cnf, $chaining_key, $input_key_material, $num_outputs ) = @_;

  my $temp_key = hmac( $input_key_material, $chaining_key, $cnf->{hash_func} );

  my $out1 = hmac( pack( "H*", "01" ), $temp_key, $cnf->{hash_func} );
  return $out1 if ( $num_outputs == 1 );

  my $out2 = hmac( $out1 || pack( "H*", "02" ), $temp_key, $cnf->{hash_func} );
  return ( $out1, $out2 ) if ( $num_outputs == 2 );

  my $out3 = hmac( $out2 || pack( "H*", "03" ), $temp_key, $cnf->{hash_func} );
  return ( $out1, $out2, $out3 ) if ( $num_outputs == 3 );
}

sub init_symmetric_state {
  my ( $cnf, $hs ) = @_;

  my $protocol_name = $hs->{protocol_name};

  my %ss;

  if ( length( $protocol_name ) <= $cnf->{hash_len} ) {
    my $x = ( '00' ) x ( $cnf->{hash_len} - length( $protocol_name ) );
    $ss{h} = $protocol_name . pack( "H*", $x );
  } else {
    $ss{h} = $cnf->{hash_func}->( $protocol_name );
  }

  $ss{ck} = $ss{h};

  $hs->{ss} = \%ss;

  return $hs;
} ## end sub init_symmetric_state

sub mix_key {
# mix_key
  my ( $cnf, $ss, $dh ) = @_;
  # old ss.ck: unpack("H*", $ss->{ck})
  ( $ss->{ck}, $ss->{k} ) = noise_hkdf( $cnf, $ss->{ck}, $dh, 2 );
  init_key( $ss, $ss->{k} );
  # ss.ck: unpack("H*", $ss->{ck})
  # ss.k: unpack("H*", $ss->{k})
  return $ss;
}

sub mix_hash {
  # mix_hash
  my ( $cnf, $ss, $data ) = @_;
  #  ss.old_h: unpack("H*", $ss->{h})
  #  data: unpack("H*", $data)
  $ss->{h} = $cnf->{hash_func}->( $ss->{h} . $data );
  #  ss.h: unpack("H*", $ss->{h})
  return $ss;
}

sub init_key {
  my ( $ss, $k ) = @_;
  $ss->{k} = $k;
  $ss->{n} = 0;
  return $ss;
}

sub has_key {
  my ( $ss ) = @_;
  return $ss->{k} ? 1 : 0;
}

sub set_nonce {
  my ( $ss, $n ) = @_;
  $ss->{n} = $n;
  return $ss;
}

sub mix_keyandhash {
  my ( $cnf, $ss, $data ) = @_;
  my $temp_h;
  my $temp_k;
  ( $ss->{ck}, $temp_h, $temp_k ) = noise_hkdf( $cnf, $ss->{ck}, $data, 3 );
  mix_hash( $cnf, $ss, $temp_h );
  if ( length( $temp_k ) > $cnf->{hash_len} ) {
    $temp_k = substr( $temp_k, 0, $cnf->{hash_len} );
  }
  init_key( $ss, $temp_k );
  #  ss.h: unpack("H*", $ss->{h})
  return $ss;
}

sub noise_split {
  my ( $cnf,     $ss )      = @_;
  my ( $temp_k1, $temp_k2 ) = noise_hkdf( $cnf, $ss->{k}, '', 2 );
  if ( length( $temp_k1 ) > $cnf->{hash_len} ) {
    $temp_k1 = substr( $temp_k1, 0, $cnf->{hash_len} );
    $temp_k2 = substr( $temp_k2, 0, $cnf->{hash_len} );
  }

  my $c1_ss = {};
  init_key( $c1_ss, $temp_k1 );
  my $c2_ss = {};
  init_key( $c2_ss, $temp_k2 );

  return ( $c1_ss, $c2_ss );
}

sub init_ciphersuite_name {

  #ciphersuite_name => secp256r1_AESGCM_SHA256
  my ( $cnf ) = @_;
  $cnf->{ciphersuite_name} = join( "_", @{$cnf}{qw/group_name cipher_name hash_name/} );
  return $cnf->{ciphersuite_name};
}

sub init_handshake_pattern {
  my ( $hs ) = @_;
  $hs->{pattern} = get_pattern_by_name( $hs->{pattern_name} );

  #psk
  my $psk_modifier = '';
  if ( $hs->{psk} ) {
    my $psk_id = $hs->{psk_id};
    $psk_modifier = "psk$psk_id";
    if ( $psk_id == 0 ) {
      unshift @{ $hs->{pattern}{messages}[0] }, 'psk';
    } else {
      push @{ $hs->{pattern}{messages}[ $psk_id - 1 ] }, 'psk';
    }
  }

  $hs->{psk_modifier} = $psk_modifier;

  return $hs->{pattern};
} ## end sub init_handshake_pattern

sub init_protocol_name {
  my ( $cnf, $hs ) = @_;
  $hs->{protocol_name} = join( "_", "XNoise", join("-", $hs->{pattern_name} , $hs->{psk_modifier}), $cnf->{ciphersuite_name} );
  return $hs->{protocol_name};
}

sub new_handshake_state {
  my ( $cnf, $hs ) = @_;

  #conf => noise_conf,
  #pattern_name => NN, ...
  #initiator
  #prologue => some_info
  #psk
  #psk_id
  #s_priv: local_long_term_priv
  #s_pub: local_long_term_pub
  #m_priv: local_middle_term_priv
  #m_pub: local_middle_term_pub
  #e_priv: local_ephemeral_priv
  #e_pub: local_ephemeral_pub
  #rs_pub: peer_long_term_pub
  #rm_pub: peer_middle_term_pub
  #re_pub: peer_ephemeral_pub
  #s_pub_type: raw = compressed point, id = digest of raw, cert, sn = cert serial number

  ### begin hs new_handshake_state: $hs->{initiator}

  $hs->{should_write} = $hs->{initiator};
  $hs->{msg_id}       = 0;

  init_handshake_pattern( $hs );
  init_protocol_name( $cnf, $hs );
  init_symmetric_state( $cnf, $hs );

  ### prologue: $hs->{prologue}
  mix_hash( $cnf, $hs->{ss}, $hs->{prologue} );

  for my $m ( @{ $hs->{pattern}{initiator_pre_messages} } ) {
    ### initiator_pre_message: $m
    if ( $hs->{initiator} and ( $m eq 's' ) ) {
      ### i-is: unpack("H*", $hs->{s_pub_bin})
      mix_hash( $cnf, $hs->{ss}, $hs->{s_pub_bin} );
    } elsif ( $hs->{initiator} and ( $m eq 'm' ) ) {
      ### i-im: unpack("H*", $hs->{m_pub_bin})
      mix_hash( $cnf, $hs->{ss}, $hs->{m_pub_bin} );
    } elsif ( $hs->{initiator} and ( $m eq 'e' ) ) {
      ### i-ie: unpack("H*", $hs->{e_pub_bin})
      mix_hash( $cnf, $hs->{ss}, $hs->{e_pub_bin} );
    } elsif ( ( !$hs->{initiator} ) and ( $m eq 's' ) ) {
      ### r-is: unpack("H*", $hs->{rs_pub_bin})
      mix_hash( $cnf, $hs->{ss}, $hs->{rs_pub_bin} );
    } elsif ( ( !$hs->{initiator} ) and ( $m eq 'm' ) ) {
      ### r-im: unpack("H*", $hs->{rm_pub_bin})
      mix_hash( $cnf, $hs->{ss}, $hs->{rm_pub_bin} );
    } elsif ( ( !$hs->{initiator} ) and ( $m eq 'e' ) ) {
      ### r-ie: unpack("H*", $hs->{re_pub_bin})
      mix_hash( $cnf, $hs->{ss}, $hs->{re_pub_bin} );
    }
  }

  for my $m ( @{ $hs->{pattern}{responder_pre_messages} } ) {
    ### responder_pre_messages: $m
    if ( $hs->{initiator} and ( $m eq 's' ) ) {
      ### i-rs: unpack("H*", $hs->{rs_pub_bin})
      mix_hash( $cnf, $hs->{ss}, $hs->{rs_pub_bin} );
    } elsif ( $hs->{initiator} and ( $m eq 'm' ) ) {
      ### i-rm: unpack("H*", $hs->{rm_pub_bin})
      mix_hash( $cnf, $hs->{ss}, $hs->{rm_pub_bin} );
    } elsif ( $hs->{initiator} and ( $m eq 'e' ) ) {
      ### i-re: unpack("H*", $hs->{re_pub_bin})
      mix_hash( $cnf, $hs->{ss}, $hs->{re_pub_bin} );
    } elsif ( ( !$hs->{initiator} ) and ( $m eq 's' ) ) {
      ### r-rs: unpack("H*", $hs->{s_pub_bin})
      mix_hash( $cnf, $hs->{ss}, $hs->{s_pub_bin} );
    } elsif ( ( !$hs->{initiator} ) and ( $m eq 'm' ) ) {
      ### r-rm: unpack("H*", $hs->{m_pub_bin})
      mix_hash( $cnf, $hs->{ss}, $hs->{m_pub_bin} );
    } elsif ( ( !$hs->{initiator} ) and ( $m eq 'e' ) ) {
      ### r-re: unpack("H*", $hs->{e_pub_bin})
      mix_hash( $cnf, $hs->{ss}, $hs->{e_pub_bin} );
    }
  }

  return $hs;
} ## end sub new_handshake_state

sub rekey {
  my ( $cnf, $hs ) = @_;

  my $iv      = 2**64 - 1;
  my $zerolen = '';
  my $zeros   = pack( "H*", ( '00' ) x $cnf->{key_len} );

  my ( $ciphertext, $authtag ) = $cnf->{enc_func}->( $hs->{ss}{k}, $iv, $zerolen, $zeros );
  $hs->{ss}{k} = substr $ciphertext, 0, $cnf->{key_len};
  return $hs->{ss}{k};
}

sub encrypt_with_ad {
  my ( $cnf, $ss, $ad, $plaintext ) = @_;

  return $plaintext unless ( has_key( $ss ) );

  ### ss.k: unpack("H*", $ss->{k})
  ### ss.n: $ss->{n}
  ### ad: unpack("H*", $ad)
  ### plaintext: unpack("H*", $plaintext)
  my @cipher_info = $cnf->{enc_func}->( $ss->{k}, $ss->{n}, $ad, $plaintext );
  ### @cipher_info

  my $ciphertext = $cnf->{msg_pack_func}->( \@cipher_info );

  $ss->{n}++;

  return $ciphertext;
} ## end sub encrypt_with_ad

sub decrypt_with_ad {
  my ( $cnf, $ss, $ad, $ciphertext ) = @_;

  return $ciphertext unless ( has_key( $ss ) );

  my $cipher_info_r = $cnf->{msg_unpack_func}->( $ciphertext );
  my $plaintext     = $cnf->{dec_func}->( $ss->{k}, $ss->{n}, $ad, @$cipher_info_r );

  $ss->{n}++;

  return $plaintext;
}

sub encrypt_and_hash {
  my ( $cnf, $out, $ss, $plaintext ) = @_;

  my $cipherinfo = encrypt_with_ad( $cnf, $ss, $ss->{h}, $plaintext );
  mix_hash( $cnf, $ss, $cipherinfo );

  push @$out, $cipherinfo;
  return $out;
}

sub decrypt_and_hash {
  my ( $cnf, $out, $ss, $cipher_info ) = @_;

  my $plaintext = decrypt_with_ad( $cnf, $ss, $ss->{h}, $cipher_info );

  mix_hash( $cnf, $ss, $cipher_info );

  push @$out, $plaintext;
  return $out;
}

sub derive_session_key_iv {
  my ( $cnf, $k, $salt ) = @_;

  # hkdf($keying_material, $salt, $hash_name, $len, $info);
  my $key = hkdf( $k, $salt, $cnf->{hash_name}, $cnf->{key_len}, "XNoise Session Key" );
  my $iv  = hkdf( $k, $salt, $cnf->{hash_name}, $cnf->{iv_len},  "XNoise Session IV" );

  return ( $key, $iv );
}

sub session_encrypt {
  my ( $cnf, $key, $iv, $aad, $plaintext ) = @_;

  #time: make sure the iv_xor_time is different
  my $time = time();

  my $iv_xor_time = pack( "B*", unpack( "B*", $iv ) ^ unpack( "B*", $time ) );

  my ( $ciphertext, $authtag ) = $cnf->{enc_func}->( $key, $iv_xor_time, $aad, $plaintext );

  my $cipherinfo = $cnf->{msg_pack_func}->( [ $time, $ciphertext, $authtag ] );

  ### noise session encrypt
  ### key: unpack("H*", $key)
  ### iv: unpack("H*", $iv)
  ### time: unpack("H*", $time)
  ### iv_xor_time: unpack("H*", $iv_xor_time)
  ### aad: unpack("H*", $aad)
  ### plaintext: unpack("H*", $plaintext)
  ### ciphertext: unpack("H*", $ciphertext)
  ### authtag: unpack("H*", $authtag)
  ### cipherinfo: unpack("H*", $cipherinfo)

  return $cipherinfo;
} ## end sub session_encrypt

sub session_decrypt {
  my ( $cnf, $key, $iv, $aad, $cipherinfo ) = @_;

  my $d = $cnf->{msg_unpack_func}->( $cipherinfo );
  my ( $time, $ciphertext, $authtag ) = @$d;

  my $iv_xor_time = pack( "B*", unpack( "B*", $iv ) ^ unpack( "B*", $time ) );

  my $plaintext = $cnf->{dec_func}->( $key, $iv_xor_time, $aad, $ciphertext, $authtag );

  ### noise session decrypt
  ### key: unpack("H*", $key)
  ### iv: unpack("H*", $iv)
  ### aad: unpack("H*", $aad)
  ### cipherinfo: unpack("H*", $cipherinfo)
  ### time: unpack("H*", $time)
  ### iv_xor_time: unpack("H*", $iv_xor_time)
  ### authtag: unpack("H*", $authtag)
  ### ciphertext: unpack("H*", $ciphertext)
  ### plaintext: unpack("H*", $plaintext)

  return $plaintext;
} ## end sub session_decrypt

sub write_message {
  my ( $cnf, $hs, $out, $payload ) = @_;

  if ( !$hs->{should_write} ) {
    return;
  }

  my $m_pattern_len = @{ $hs->{pattern}{messages} };
  if ( $hs->{msg_id} > $m_pattern_len - 1 ) {
    return;
  }

  for my $m ( @{ $hs->{pattern}{messages}[ $hs->{msg_id} ] } ) {
    ### write message pattern: $m
    if ( $m eq 'e' ) {

      my $e_key_r = generate_ec_key( $cnf->{ec_params}{group}, undef, 2, $cnf->{ec_params}{ctx} );
      $hs->{e_pub}      = $e_key_r->{pub_pkey};
      $hs->{e_priv}     = $e_key_r->{priv_pkey};
      $hs->{e_pub_bin}  = $e_key_r->{pub_bin};
      $hs->{e_key_pair} = $e_key_r;

      #$hs->{e_priv_file} = pem_write_evp_pkey($hs->{who} . "_e_priv.pem", $e_key_r->{priv_pkey}, 1);
      #$hs->{e_pub_file} = pem_write_evp_pkey($hs->{who} . "_e_pub.pem", $e_key_r->{pub_pkey}, 0);

      push @$out, $hs->{e_pub_bin};
      mix_hash( $cnf, $hs->{ss}, $hs->{e_pub_bin} );
      if ( $hs->{psk} ) {
        mix_key( $cnf, $hs->{ss}, $hs->{e_pub_bin} );
      }
    } elsif ( $m eq 's' ) {
      my $s_pub_info = $cnf->{msg_pack_func}->( [ $hs->{s_pub_type}, $hs->{s_pub_bin} ] );
      $out = encrypt_and_hash( $cnf, $out, $hs->{ss}, $s_pub_info );
    } elsif ( $m eq 'm' ) {
      my $m_pub_info = $cnf->{msg_pack_func}->( [ $hs->{m_pub_type}, $hs->{m_pub_bin} ] );
      $out = encrypt_and_hash( $cnf, $out, $hs->{ss}, $m_pub_info );
    } elsif ( $m eq 'ee' ) {
      mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{e_priv}, $hs->{re_pub} ) );
    } elsif ( $m eq 'es' ) {
      if ( $hs->{initiator} ) {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{e_priv}, $hs->{rs_pub} ) );
      } else {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{s_priv}, $hs->{re_pub} ) );
      }
    } elsif ( $m eq 'em' ) {
      if ( $hs->{initiator} ) {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{e_priv}, $hs->{rm_pub} ) );
      } else {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{m_priv}, $hs->{re_pub} ) );
      }
    } elsif ( $m eq 'ms' ) {
      if ( $hs->{initiator} ) {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{m_priv}, $hs->{rs_pub} ) );
      } else {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{s_priv}, $hs->{rm_pub} ) );
      }
    } elsif ( $m eq 'se' ) {
      if ( $hs->{initiator} ) {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{s_priv}, $hs->{re_pub} ) );
      } else {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{e_priv}, $hs->{rs_pub} ) );
      }
    } elsif ( $m eq 'me' ) {
      if ( $hs->{initiator} ) {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{m_priv}, $hs->{re_pub} ) );
      } else {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{e_priv}, $hs->{rm_pub} ) );
      }
    } elsif ( $m eq 'sm' ) {
      if ( $hs->{initiator} ) {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{s_priv}, $hs->{rm_pub} ) );
      } else {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{m_priv}, $hs->{rs_pub} ) );
      }
    } elsif ( $m eq 'ss' ) {
      mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{s_priv}, $hs->{rs_pub} ) );
    } elsif ( $m eq 'mm' ) {
      mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{m_priv}, $hs->{rm_pub} ) );
    } elsif ( $m eq 'psk' ) {
      mix_keyandhash( $cnf, $hs->{ss}, $hs->{psk} );
    }

    ### hs.ss.k: unpack("H*", $hs->{ss}{k})
    ### hs.ss.ck: unpack("H*", $hs->{ss}{ck})
    ### hs.ss.h: unpack("H*", $hs->{ss}{h})
  } ## end for my $m ( @{ $hs->{pattern...}})

  $hs->{should_write} = 0;
  $hs->{msg_id}++;

  ### old out: $out
  if ( defined $payload ) {
    $out = encrypt_and_hash( $cnf, $out, $hs->{ss}, $payload );
  }
  ### encrypt_and_hash out: $out

  my $out_info = $cnf->{msg_pack_func}->( $out );
  if ( $hs->{msg_id} >= $m_pattern_len ) {
    my ( $cs1, $cs2 ) = noise_split( $cnf, $hs->{ss} );
    return ( $out_info, $cs1, $cs2 );
  }

  return ( $out_info );
} ## end sub write_message

sub read_message {
  my ( $cnf, $hs, $out, $message_pack ) = @_;

  if ( $hs->{should_write} ) {
    return;
  }

  my $m_pattern_len = @{ $hs->{pattern}{messages} };
  if ( $hs->{msg_id} > $m_pattern_len - 1 ) {
    return;
  }

  my $message = $cnf->{msg_unpack_func}->( $message_pack );

  my $i = 0;

  for my $m ( @{ $hs->{pattern}{messages}[ $hs->{msg_id} ] } ) {
    ### read message pattern: $m
    if ( $m=~/^[ems]$/ ) {

      if ( $m eq 'e' ) {

        $hs->{re_pub_bin} = $message->[$i];
        $hs->{re_pub}     = evp_pkey_from_point_hex( $cnf->{ec_params}{group}, unpack( "H*", $hs->{re_pub_bin} ), $cnf->{ec_params}{ctx} );

        #$hs->{re_pub_file} = pem_write_evp_pkey( $hs->{who} . "_re_pub.pem", $hs->{re_pub}, 0 );
        mix_hash( $cnf, $hs->{ss}, $hs->{re_pub_bin} );
        if ( $hs->{psk} ) {
          mix_key( $cnf, $hs->{ss}, $hs->{re_pub_bin} );
        }
      } elsif ( $m eq 's' ) {
        my $rs_r = decrypt_and_hash( $cnf, [], $hs->{ss}, $message->[$i] );

        my $rs_pub_info_r = $cnf->{msg_unpack_func}->( $rs_r->[0] );
        my ( $rs_pub_type, $rs_pub_value ) = @$rs_pub_info_r;
        $hs->{rs_pub_bin} = $cnf->{check_rs_pub_func}->( $rs_pub_type, $rs_pub_value );

        $hs->{rs_pub} = evp_pkey_from_point_hex( $cnf->{ec_params}{group}, unpack( "H*", $hs->{rs_pub_bin} ), $cnf->{ec_params}{ctx} );

        #$hs->{rs_pub_file} = pem_write_evp_pkey( $hs->{who} . "_rs_pub.pem", $hs->{rs_pub}, 0 );
      } elsif ( $m eq 'm' ) {
        my $rm_r = decrypt_and_hash( $cnf, [], $hs->{ss}, $message->[$i] );

        my $rm_pub_info_r = $cnf->{msg_unpack_func}->( $rm_r->[0] );
        my ( $rm_pub_type, $rm_pub_value ) = @$rm_pub_info_r;
        $hs->{rm_pub_bin} = $cnf->{check_rm_pub_func}->( $rm_pub_type, $rm_pub_value );

        $hs->{rm_pub} = evp_pkey_from_point_hex( $cnf->{ec_params}{group}, unpack( "H*", $hs->{rm_pub_bin} ), $cnf->{ec_params}{ctx} );

        #$hs->{rm_pub_file} = pem_write_evp_pkey( $hs->{who} . "_rm_pub.pem", $hs->{rm_pub}, 0 );
      }

      $i++;
    } elsif ( $m eq 'ee' ) {
      mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{e_priv}, $hs->{re_pub} ) );
    } elsif ( $m eq 'es' ) {
      if ( $hs->{initiator} ) {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{e_priv}, $hs->{rs_pub} ) );
      } else {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{s_priv}, $hs->{re_pub} ) );
      }
    } elsif ( $m eq 'em' ) {
      if ( $hs->{initiator} ) {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{e_priv}, $hs->{rm_pub} ) );
      } else {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{m_priv}, $hs->{re_pub} ) );
      }
    } elsif ( $m eq 'se' ) {
      if ( $hs->{initiator} ) {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{s_priv}, $hs->{re_pub} ) );
      } else {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{e_priv}, $hs->{rs_pub} ) );
      }
    } elsif ( $m eq 'sm' ) {
      if ( $hs->{initiator} ) {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{s_priv}, $hs->{rm_pub} ) );
      } else {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{m_priv}, $hs->{rs_pub} ) );
      }
    } elsif ( $m eq 'me' ) {
      if ( $hs->{initiator} ) {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{m_priv}, $hs->{re_pub} ) );
      } else {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{e_priv}, $hs->{rm_pub} ) );
      }
    } elsif ( $m eq 'ms' ) {
      if ( $hs->{initiator} ) {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{m_priv}, $hs->{rs_pub} ) );
      } else {
        mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{s_priv}, $hs->{rm_pub} ) );
      }
    } elsif ( $m eq 'ss' ) {
      mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{s_priv}, $hs->{rs_pub} ) );
    } elsif ( $m eq 'mm' ) {
      mix_key( $cnf, $hs->{ss}, ecdh_pkey( $hs->{m_priv}, $hs->{rm_pub} ) );
    } elsif ( $m eq 'psk' ) {
      mix_keyandhash( $cnf, $hs->{ss}, $hs->{psk} );
    }

    ### hs.ss.k: unpack("H*", $hs->{ss}{k})
    ### hs.ss.ck: unpack("H*", $hs->{ss}{ck})
    ### hs.ss.h: unpack("H*", $hs->{ss}{h})
    
  } ## end for my $m ( @{ $hs->{pattern...}})

  if ( defined $message->[$i] ) {
    $out = decrypt_and_hash( $cnf, $out, $hs->{ss}, $message->[$i] );
  }
  ### out: $out

  $hs->{should_write} = 1;
  $hs->{msg_id}++;

  if ( $hs->{msg_id} >= $m_pattern_len ) {

    my ( $cs1, $cs2 ) = noise_split( $cnf, $hs->{ss} );

    return ( $out, $cs1, $cs2 );
  }

  return ( $out );
} ## end sub read_message

1;
