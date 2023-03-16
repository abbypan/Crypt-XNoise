#!/usr/bin/perl
use strict;
use warnings;

use lib '../lib';

use Test::More;

use Smart::Comments;

use Crypt::OpenSSL::EC;
use Crypt::OpenSSL::Bignum;
#use Crypt::OpenSSL::Hash2Curve;
use Crypt::OpenSSL::Base::Func;
use Crypt::XNoise;

use CBOR::XS;
use Digest::SHA qw/hmac_sha256 sha256/;
#use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use FindBin;
use POSIX qw/strftime/;

our $xnoise_conf = {
  group_name => 'prime256v1',
  #group_name             => 'secp256r1',

  hash_name => 'SHA256',
  hash_func => \&sha256,
  hash_len  => 32,

  cipher_name => 'AESGCM',
  enc_func    => sub {                 #encrypt: key, iv, aad, plaintext  -> ciphertext, authtag
    my ($key, $iv, $aad, $plain) = @_;
    #print unpack("H*", $_), "\n" for @_;
    my $tag_len = 16;
    my $res = aead_encrypt('aes-256-gcm', $plain, $aad, $key, $iv, $tag_len);
    my $ciphertext = $res->[0];
    my $tag = $res->[1];
    #print unpack("H*", $_), "\n" for ($ciphertext, $tag);
    return ($ciphertext, $tag);
  },
  dec_func => sub {                    #decrypt: key, iv, aad, ciphertext, authtag -> plaintext
    my ($key, $iv, $aad, $ciphertext, $tag) = @_;
    my $plain = aead_decrypt('aes-256-gcm', $ciphertext, $aad, $tag, $key, $iv);
    #print unpack("H*", $_), "\n" for ($plain);
    return $plain;
    #return gcm_decrypt_verify( 'AES', @d );
  },

  check_rs_pub_func => \&check_pub,
  check_rm_pub_func => \&check_pub,

  key_len     => 32,
  iv_len      => 12,
  authtag_len => 16,

  msg_pack_func   => \&encode_cbor,
  msg_unpack_func => \&decode_cbor,
};
$xnoise_conf->{ec_params} = get_ec_params( $xnoise_conf->{group_name} );
init_ciphersuite_name( $xnoise_conf );

test_one();
test_two();
test_three();
#test_four();


done_testing;

sub test_four {
### -------- test_four start ----------------

my @test_psk = ( 
    [ undef, undef ], 
    #[ 'test_psk', 0 ], 
    #[ 'test_psk', 1 ], 
    #[ 'test_psk', 2 ], 
    #[ 'test_psk', 3 ], 
    #[ 'test_psk', 4 ], 
);

for my $pattern_name ( qw/ / ) {

    #my $pattern_cnf = xnoise_pattern($pattern);
    for my $psk_r ( @test_psk ) {

        my ( $psk, $psk_id ) = @$psk_r;

        ### a send_hs_msg1
        my $a_hs = init_initiator_hs($xnoise_conf, $pattern_name, $psk, $psk_id);
        ### $a_hs
        my $a_msg_src = "init.syn";
        ### $a_msg_src
        my ( $a_msg ) = write_message( $xnoise_conf, $a_hs, [], $a_msg_src );
        ### $a_hs
        ### a_msg: unpack( "H*", $a_msg )
        

        ### b recv_hs_msg1
        my $b_hs = init_responder_hs($xnoise_conf, $pattern_name, $psk, $psk_id);
        ###   $b_hs
        my ( $b_recv_a_msg_r ) = read_message( $xnoise_conf, $b_hs, [], $a_msg );
        ###   $b_hs
        ### b_recv_a_msg: $b_recv_a_msg_r->[0]
        
        
  ### b send_hs_msg2
  my $b_msg_src = "resp.ack";
  my ( $b_msg ) = write_message( $xnoise_conf, $b_hs, [], $b_msg_src );
  ###   $b_hs
  ### b_msg: unpack("H*", $b_msg)

  ### a recv_hs_msg2
  my ( $a_recv_b_msg_r ) = read_message( $xnoise_conf, $a_hs, [], $b_msg );
  ###  $a_hs
  ###  $a_recv_b_msg_r->[0]
  
  ### a send_hs_msg3
  my $a_msg2_src = "init.ack";
  ### $a_msg2_src
  my ( $a_msg2) = write_message( $xnoise_conf, $a_hs, [], $a_msg2_src );
  ### $a_hs
  ### a_send_hs_msg3: unpack( "H*", $a_msg2 )

  ### b recv_hs_msg3
  my ( $b_recv_a_msg2_r) = read_message( $xnoise_conf, $b_hs, [], $a_msg2 );
  ### $b_hs
  ### b_recv_hs_msg3: $b_recv_a_msg2_r->[0]
  
  ### b send_hs_msg4
  my $hs_msg4_src = 'resp.ack';
  my ( $b_msg2, $b_c1, $b_c2 ) = write_message( $xnoise_conf, $b_hs, [], $hs_msg4_src);
  ### $b_hs
  ### b send_hs_msg4: unpack( "H*", $b_msg2 )
  ### $b_c1
  ### $b_c2

  ### a recv_hs_msg4
  my ( $a_recv_b_msg2_r, $a_c1, $a_c2 ) = read_message( $xnoise_conf, $a_hs, [], $b_msg2 );
  ### $a_hs
  ### a_recv_hs_msg4: $a_recv_b_msg2_r->[0]
  ### $a_c1
  ### $a_c2
  

        # a -> b : plain_a  -> trans_cipherinfo_a
        my $plain_a = 'fujian quanzhou 666';
        ### a send_comm_msg1: $plain_a
        my ( $a_c1_key, $a_c1_iv ) = derive_session_key_iv( $xnoise_conf, $a_c1->{k}, '' );
        my $a_trans_cipherinfo_b = session_encrypt( $xnoise_conf, $a_c1_key, $a_c1_iv, $a_hs->{ss}{h}, $plain_a );

        ### b recv_comm_msg1
        my ( $b_c1_key, $b_c1_iv ) = derive_session_key_iv( $xnoise_conf, $b_c1->{k}, '' );
        my $b_recv_plaintext_a = session_decrypt( $xnoise_conf, $b_c1_key, $b_c1_iv, $b_hs->{ss}{h}, $a_trans_cipherinfo_b );
        ### $b_recv_plaintext_a

        # b -> a : plain_b -> trans_cipherinfo_b
        my $plain_b = 'anhui hefei 888';
        ### b send_comm_msg2: $plain_b
        my ( $b_c2_key, $b_c2_iv ) = derive_session_key_iv( $xnoise_conf, $b_c2->{k}, '' );
        my $b_trans_cipherinfo_a = session_encrypt( $xnoise_conf, $b_c2_key, $b_c2_iv, $b_hs->{ss}{h}, $plain_b );

        ### a recv_comm_msg2
        my ( $a_c2_key, $a_c2_iv ) = derive_session_key_iv( $xnoise_conf, $a_c2->{k}, '' );
        my $a_recv_plaintext_b = session_decrypt( $xnoise_conf, $a_c2_key, $a_c2_iv, $a_hs->{ss}{h}, $b_trans_cipherinfo_a );
        ### $a_recv_plaintext_b

        is( $plain_a, $b_recv_plaintext_a, "$pattern_name: plain_a" );
        is( $plain_b, $a_recv_plaintext_b, "$pattern_name: plain_b" );

        ### -----------end test --------: $pattern_name, $psk, $psk_id
    } ## end for my $psk_r ( @test_psk)
} ## end for my $pattern_name ( ...)

### ---------test_four end ----------------
}

sub test_three {
### -------- test_three start ----------------

my @test_psk = ( 
    [ undef, undef ], 
    [ 'test_psk', 0 ], 
    [ 'test_psk', 1 ], 
    [ 'test_psk', 2 ], 
    [ 'test_psk', 3 ], 
);

#XX-X'X'
#XX1-X'X'1
#XK-X'K'
my @test_pattern = (qw/
NK-X'K'
NX-X'X'
    /);

for my $pattern_name (  @test_pattern ) {

    #my $pattern_cnf = xnoise_pattern($pattern);
    for my $psk_r ( @test_psk ) {

        my ( $psk, $psk_id ) = @$psk_r;

        ### a send_hs_msg1
        my $a_hs = init_initiator_hs($xnoise_conf, $pattern_name, $psk, $psk_id);
        ### $a_hs
        my $a_msg_src = "init.syn";
        ### $a_msg_src
        my ( $a_msg ) = write_message( $xnoise_conf, $a_hs, [], $a_msg_src );
        ### $a_hs
        ### a_msg: unpack( "H*", $a_msg )
        

        ### b recv_hs_msg1
        my $b_hs = init_responder_hs($xnoise_conf, $pattern_name, $psk, $psk_id);
        ###   $b_hs
        my ( $b_recv_a_msg_r ) = read_message( $xnoise_conf, $b_hs, [], $a_msg );
        ###   $b_hs
        ### b_recv_a_msg: $b_recv_a_msg_r->[0]
        
        
  ### b send_hs_msg2
  my $b_msg_src = "resp.ack";
  my ( $b_msg ) = write_message( $xnoise_conf, $b_hs, [], $b_msg_src );
  ###   $b_hs
  ### b_msg: unpack("H*", $b_msg)

  ### a recv_hs_msg2
  my ( $a_recv_b_msg_r ) = read_message( $xnoise_conf, $a_hs, [], $b_msg );
  ###  $a_hs
  ###  $a_recv_b_msg_r->[0]
  
  ### a send_hs_msg3
  my $a_msg2_src = "init.ack";
  ### $a_msg2_src
  my ( $a_msg2, $a_c1, $a_c2 ) = write_message( $xnoise_conf, $a_hs, [], $a_msg2_src );
  ### $a_hs
  ### a_send_hs_msg3: unpack( "H*", $a_msg2 )
  ### $a_c1
  ### $a_c2

  ### b recv_hs_msg3
  my ( $b_recv_a_msg2_r, $b_c1, $b_c2 ) = read_message( $xnoise_conf, $b_hs, [], $a_msg2 );
  ### $b_hs
  ### b_recv_hs_msg3: $b_recv_a_msg2_r->[0]
  ### $b_c1
  ### $b_c2
  

        # a -> b : plain_a  -> trans_cipherinfo_a
        my $plain_a = 'fujian quanzhou 666';
        ### a send_comm_msg1: $plain_a
        my ( $a_c1_key, $a_c1_iv ) = derive_session_key_iv( $xnoise_conf, $a_c1->{k}, '' );
        my $a_trans_cipherinfo_b = session_encrypt( $xnoise_conf, $a_c1_key, $a_c1_iv, $a_hs->{ss}{h}, $plain_a );

        ### b recv_comm_msg1
        my ( $b_c1_key, $b_c1_iv ) = derive_session_key_iv( $xnoise_conf, $b_c1->{k}, '' );
        my $b_recv_plaintext_a = session_decrypt( $xnoise_conf, $b_c1_key, $b_c1_iv, $b_hs->{ss}{h}, $a_trans_cipherinfo_b );
        ### $b_recv_plaintext_a

        # b -> a : plain_b -> trans_cipherinfo_b
        my $plain_b = 'anhui hefei 888';
        ### b send_comm_msg2: $plain_b
        my ( $b_c2_key, $b_c2_iv ) = derive_session_key_iv( $xnoise_conf, $b_c2->{k}, '' );
        my $b_trans_cipherinfo_a = session_encrypt( $xnoise_conf, $b_c2_key, $b_c2_iv, $b_hs->{ss}{h}, $plain_b );

        ### a recv_comm_msg2
        my ( $a_c2_key, $a_c2_iv ) = derive_session_key_iv( $xnoise_conf, $a_c2->{k}, '' );
        my $a_recv_plaintext_b = session_decrypt( $xnoise_conf, $a_c2_key, $a_c2_iv, $a_hs->{ss}{h}, $b_trans_cipherinfo_a );
        ### $a_recv_plaintext_b

        is( $plain_a, $b_recv_plaintext_a, "$pattern_name: plain_a" );
        is( $plain_b, $a_recv_plaintext_b, "$pattern_name: plain_b" );

        ### -----------end test --------: $pattern_name, $psk, $psk_id
    } ## end for my $psk_r ( @test_psk)
} ## end for my $pattern_name ( ...)

### ---------test_three end ----------------
}


sub test_two {
### -------- test_two start ----------------

my @test_psk = ( 
    [ undef, undef ], 
    [ 'test_psk', 0 ], 
    [ 'test_psk', 1 ], 
    [ 'test_psk', 2 ], 
);

my @test_pattern = (qw/
NK-N'K'
KK-K'K'
IK-I'K'
IX-I'X'
NX-N'X'
NK1-N'K'1
    /);

for my $pattern_name ( @test_pattern ) {

    #my $pattern_cnf = xnoise_pattern($pattern);
    for my $psk_r ( @test_psk ) {

        my ( $psk, $psk_id ) = @$psk_r;

        ### a send_hs_msg1
        my $a_hs = init_initiator_hs($xnoise_conf, $pattern_name, $psk, $psk_id);
        ### $a_hs
        my $a_msg_src = "init.syn";
        ### $a_msg_src
        my ( $a_msg ) = write_message( $xnoise_conf, $a_hs, [], $a_msg_src );
        ### $a_hs
        ### a_msg: unpack( "H*", $a_msg )
        

        ### b recv_hs_msg1
        my $b_hs = init_responder_hs($xnoise_conf, $pattern_name, $psk, $psk_id);
        ###   $b_hs
        my ( $b_recv_a_msg_r ) = read_message( $xnoise_conf, $b_hs, [], $a_msg );
        ###   $b_hs
        ### b_recv_a_msg: $b_recv_a_msg_r->[0]
        
        
  ### b send_hs_msg2
  my $b_msg_src = "resp.ack";
  my ( $b_msg, $b_c1, $b_c2 ) = write_message( $xnoise_conf, $b_hs, [], $b_msg_src );
  ###   $b_hs
  ### b_msg: unpack("H*", $b_msg)
  ###   $b_c1
  ###   $b_c2

  ### a recv_hs_msg2
  my ( $a_recv_b_msg_r, $a_c1, $a_c2 ) = read_message( $xnoise_conf, $a_hs, [], $b_msg );
  ###  $a_hs
  ###  $a_recv_b_msg_r->[0]
  ###  $a_c1
  ###  $a_c2
  

        # a -> b : plain_a  -> trans_cipherinfo_a
        my $plain_a = 'fujian quanzhou 666';
        ### a send_comm_msg1: $plain_a
        my ( $a_c1_key, $a_c1_iv ) = derive_session_key_iv( $xnoise_conf, $a_c1->{k}, '' );
        my $a_trans_cipherinfo_b = session_encrypt( $xnoise_conf, $a_c1_key, $a_c1_iv, $a_hs->{ss}{h}, $plain_a );

        ### b recv_comm_msg1
        my ( $b_c1_key, $b_c1_iv ) = derive_session_key_iv( $xnoise_conf, $b_c1->{k}, '' );
        my $b_recv_plaintext_a = session_decrypt( $xnoise_conf, $b_c1_key, $b_c1_iv, $b_hs->{ss}{h}, $a_trans_cipherinfo_b );
        ### $b_recv_plaintext_a

        # b -> a : plain_b -> trans_cipherinfo_b
        my $plain_b = 'anhui hefei 888';
        ### b send_comm_msg2: $plain_b
        my ( $b_c2_key, $b_c2_iv ) = derive_session_key_iv( $xnoise_conf, $b_c2->{k}, '' );
        my $b_trans_cipherinfo_a = session_encrypt( $xnoise_conf, $b_c2_key, $b_c2_iv, $b_hs->{ss}{h}, $plain_b );

        ### a recv_comm_msg2
        my ( $a_c2_key, $a_c2_iv ) = derive_session_key_iv( $xnoise_conf, $a_c2->{k}, '' );
        my $a_recv_plaintext_b = session_decrypt( $xnoise_conf, $a_c2_key, $a_c2_iv, $a_hs->{ss}{h}, $b_trans_cipherinfo_a );
        ### $a_recv_plaintext_b

        is( $plain_a, $b_recv_plaintext_a, "$pattern_name: plain_a" );
        is( $plain_b, $a_recv_plaintext_b, "$pattern_name: plain_b" );

        ### -----------end test --------: $pattern_name, $psk, $psk_id
    } ## end for my $psk_r ( @test_psk)
} ## end for my $pattern_name ( ...)

### ---------test_two end ----------------
}

sub test_one {
### -------- test one start ----------------

my @test_psk = ( 
    [ undef, undef ], 
    [ 'test_psk', 0 ], 
    [ 'test_psk', 1 ], 
);

my @test_pattern = (qw/
N-N'
K-K'
X-X'
N-X'
/);

for my $pattern_name ( @test_pattern ) {

    #my $pattern_cnf = xnoise_pattern($pattern);
    for my $psk_r ( @test_psk ) {

        my ( $psk, $psk_id ) = @$psk_r;

        ### a send_hs_msg1
        my $a_hs = init_initiator_hs($xnoise_conf, $pattern_name, $psk, $psk_id);
        ### $a_hs
        my $a_msg_src = "init.syn";
        ### $a_msg_src
        my ( $a_msg, $a_c1, $a_c2 ) = write_message( $xnoise_conf, $a_hs, [], $a_msg_src );
        ### $a_hs
        ### a_msg: unpack( "H*", $a_msg )
        ### $a_c1
        ### $a_c2
        

        ### b recv_hs_msg1
        my $b_hs = init_responder_hs($xnoise_conf, $pattern_name, $psk, $psk_id);
        ###   $b_hs
        my ( $b_recv_a_msg_r, $b_c1, $b_c2 ) = read_message( $xnoise_conf, $b_hs, [], $a_msg );
        ###   $b_hs
        ### b_recv_a_msg: $b_recv_a_msg_r->[0]
        ### $b_c1
        ### $b_c2

        # a -> b : plain_a  -> trans_cipherinfo_a
        my $plain_a = 'fujian quanzhou 666';
        ### a send_comm_msg1: $plain_a
        my ( $a_c1_key, $a_c1_iv ) = derive_session_key_iv( $xnoise_conf, $a_c1->{k}, '' );
        my $a_trans_cipherinfo_b = session_encrypt( $xnoise_conf, $a_c1_key, $a_c1_iv, $a_hs->{ss}{h}, $plain_a );

        ### b recv_comm_msg1
        my ( $b_c1_key, $b_c1_iv ) = derive_session_key_iv( $xnoise_conf, $b_c1->{k}, '' );
        my $b_recv_plaintext_a = session_decrypt( $xnoise_conf, $b_c1_key, $b_c1_iv, $b_hs->{ss}{h}, $a_trans_cipherinfo_b );
        ### $b_recv_plaintext_a

        # b -> a : plain_b -> trans_cipherinfo_b
        my $plain_b = 'anhui hefei 888';
        ### b send_comm_msg2: $plain_b
        my ( $b_c2_key, $b_c2_iv ) = derive_session_key_iv( $xnoise_conf, $b_c2->{k}, '' );
        my $b_trans_cipherinfo_a = session_encrypt( $xnoise_conf, $b_c2_key, $b_c2_iv, $b_hs->{ss}{h}, $plain_b );

        ### a recv_comm_msg2
        my ( $a_c2_key, $a_c2_iv ) = derive_session_key_iv( $xnoise_conf, $a_c2->{k}, '' );
        my $a_recv_plaintext_b = session_decrypt( $xnoise_conf, $a_c2_key, $a_c2_iv, $a_hs->{ss}{h}, $b_trans_cipherinfo_a );
        ### $a_recv_plaintext_b

        is( $plain_a, $b_recv_plaintext_a, "$pattern_name: plain_a" );
        is( $plain_b, $a_recv_plaintext_b, "$pattern_name: plain_b" );

        ### -----------end test --------: $pattern_name, $psk, $psk_id
    } ## end for my $psk_r ( @test_psk)
} ## end for my $pattern_name ( ...)

### ---------test one end ----------------
}

sub init_initiator_hs {
my ($xnoise_conf, $pattern_name, $psk, $psk_id) = @_;

### -----------start a_hs --------: $pattern_name, $psk, $psk_id
my $a_hs = new_handshake_state(
    $xnoise_conf,
    { who          => 'a',
        pattern_name => $pattern_name,
        initiator    => 1,
        prologue     => 'some_info',

        psk    => $psk,
        psk_id => $psk_id,

        s_priv => pem_read_pkey( $FindBin::Bin . '/a_s_priv.pem', 1 ),
        s_pub  => pem_read_pkey( $FindBin::Bin . '/a_s_pub.pem',  0 ),
        m_priv => pem_read_pkey( $FindBin::Bin . '/a_m_priv.pem', 1 ),
        m_pub  => pem_read_pkey( $FindBin::Bin . '/a_m_pub.pem',  0 ),
        rs_pub => pem_read_pkey( $FindBin::Bin . '/b_s_pub.pem',  0 ),
        rm_pub => pem_read_pkey( $FindBin::Bin . '/b_m_pub.pem',  0 ),

        s_pub_type  => 'raw',
        s_pub_bin   => pack( "H*", pem_read_pub_hex( $FindBin::Bin . '/a_s_pub.pem', 2 ) ),

        m_pub_type  => 'raw',
        m_pub_bin   => pack( "H*", pem_read_pub_hex( $FindBin::Bin . '/a_m_pub.pem', 2 ) ),

        rs_pub_type => 'raw',
        rs_pub_bin  => pack( "H*", pem_read_pub_hex( $FindBin::Bin . '/a_rs_pub.pem', 2 ) ),

        rm_pub_type => 'raw',
        rm_pub_bin  => pack( "H*", pem_read_pub_hex( $FindBin::Bin . '/a_rm_pub.pem', 2 ) ),
    },
);
return $a_hs;
}

sub init_responder_hs {

my ($xnoise_conf, $pattern_name, $psk, $psk_id) = @_;
        ### -----------start bs --------: $pattern_name, $psk, $psk_id
        my $b_hs = new_handshake_state(
            $xnoise_conf,
            { who => 'b',

                pattern_name => $pattern_name,

                initiator => 0,
                prologue  => 'some_info',

                psk    => $psk,
                psk_id => $psk_id,

                s_priv => pem_read_pkey( $FindBin::Bin . '/b_s_priv.pem', 1 ),
                s_pub  => pem_read_pkey( $FindBin::Bin . '/b_s_pub.pem',  0 ),

                m_priv => pem_read_pkey( $FindBin::Bin . '/b_m_priv.pem', 1 ),
                m_pub  => pem_read_pkey( $FindBin::Bin . '/b_m_pub.pem',  0 ),

                rs_pub => pem_read_pkey( $FindBin::Bin . '/a_s_pub.pem',  0 ),
                rm_pub => pem_read_pkey( $FindBin::Bin . '/a_m_pub.pem',  0 ),

                s_pub_type  => 'raw',
                s_pub_bin   => pack( "H*", pem_read_pub_hex( $FindBin::Bin . '/b_s_pub.pem', 2 ) ),

                rs_pub_type => 'raw',
                rs_pub_bin  => pack( "H*", pem_read_pub_hex( $FindBin::Bin . '/b_rs_pub.pem', 2 ) ),

                m_pub_type  => 'raw',
                m_pub_bin   => pack( "H*", pem_read_pub_hex( $FindBin::Bin . '/b_m_pub.pem', 2 ) ),

                rm_pub_type => 'raw',
                rm_pub_bin  => pack( "H*", pem_read_pub_hex( $FindBin::Bin . '/b_rm_pub.pem', 2 ) ),
            } );
        return $b_hs;
}

sub check_pub {
    my ( $type, $value ) = @_;
    ### check pub : $type, unpack("H*", $value)

    if ( $type eq 'raw' ) {

        #check the value is in the TOFU (trust on first use) record or not
        return $value;                     #pub raw
    }

    if ( $type eq 'id' ) {

        #check the value is in the TOFU (trust on first use) record or not
        #map value to the pub raw
    }

    if ( $type eq 'sn' ) {

        #check the value is in the TOFU (trust on first use) record or not
        #map value to the cert, extract the pub raw from cert
    }

    if ( $type eq 'cert' ) {

        #check the value is in the TOFU (trust on first use) record or not
        #if not, check_cert_avail
        #extract the pub raw from cert
    }
} ## end sub check_pub_s
