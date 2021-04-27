package Crypto::API;

=head1 NAME

Crypto::API - Universal Plug & Play API

=head1 USAGE

This module mainly used by Inheritance

 package Exchange {
     use Moo;
     extends 'Crypto::API';
 }

You can use this module as parent and the child class
can simply define the api spec.

 package foo {
    use Moo;
    extends 'Crypto::API';

    sub _build_base_url {
        URI->new('https://api.kucoin.com');
    }

    sub set_prices {{
        request => {
            method => 'get',
            path   => '/api/v1/market/stats',
            data   => {
                pair => 'symbol',
            },
        },
        response => {
            key => 'data',
            row => {
                pair       => 'symbol',
                last_price => 'last',
            },
        },
    }}
 }

The main purpose of this is to normalise the request and response
for different exchanges that using this API as a standard.

So if you call price data from Binance and Kucoin or etc ...

There will be no different.

 $binance->prices(pair => 'XRP-USDC') -> getting { pair => 'XRP-USDC', last_price => 1234 };

OR

 $kucoin->prices(pair => 'XRP-USDC') -> getting { pair => 'XRP-USDC', last_price => 1234 };

=cut

use Moo;
use URI::Escape  qw( uri_escape );
use Digest::SHA  qw( hmac_sha256_hex );
use MIME::Base64 qw( encode_base64 );
use HTTP::API::Client;

extends 'HTTP::API::Client';

sub do_hmac_sha256_hex {
    my ($self, $str, $secret) = @_;
    return hmac_sha256_hex($str, $secret);
}

sub do_hmac_sha256_base64 {
    my ($self, $str, $secret) = @_;
    return encode_base64( hmac_sha256(@_) );
}

our $AUTOLOAD = '';

sub AUTOLOAD {
    my ($self, @args) = @_;

    my ($function) = reverse split /::/, $AUTOLOAD;

    if (!$self->can("set_$function")) {
        die "Can't call method '$function'";
    }

    return $self->_call_function(func => $function, @args);
}

sub _call_function {
    my ($self, %o) = @_;

    my $function = delete $o{func}
        or die "What is the function name??";

    my $route_spec_func = "set_$function";

    my $route = $self->$route_spec_func;

    my ($req_spec, $resp_spec) = @$route{qw(request response)};

    if (!$req_spec) {
        die 'Missing request';
    }

    if (!$resp_spec) {
        die 'Missing response';
    }

    my ($method, $path, $data, $headers, $events) = @$req_spec{qw{
         method   path   data   headers   events
    }};

    if (!$method) {
        die 'Missing method';
    }

    if (!$path) {
        die 'Missing path or URL';
    }

    my %mapped_data = ();

    $data ||= {};

    $events->{not_include} = {};

    while (my ($my_alias, $setting) = each %$data) {
        my ($to_exchange, $required, $default, $include);

        if (ref $setting eq 'HASH') {
            $to_exchange = $setting->{field_name}
                or die "Missing setting: field_name";
            ($required, $default, $include) = @$setting{qw(required default include)};
        }
        else {
            $to_exchange = $setting;
        }

        $include ||= '';

        my $value = $o{$my_alias};

        if (!defined $value) {
            if ($required) {
                die "Missing argument: $my_alias";
            }
            elsif ($default) {
                if (ref $default eq 'CODE') {
                    $value = $self->$default($my_alias, $setting);
                }
                else {
                    $value = $default;
                }
            }
        }

        my $format = "request_attr_$my_alias";

        if ($self->can($format)) {
            $value = $self->$format($value);
        }

        if (defined($value) || $include eq 'always') {
            $mapped_data{$to_exchange} = $value;
        }
        else {
            $events->{not_include}{$to_exchange} = 1;
        }
    }

    if (my $code = $events->{keys}) {
        my @events_keys;

        if (ref $code eq 'CODE') {
            @events_keys = $code->();
        }
        elsif (ref $code eq 'ARRAY') {
            @events_keys = @$code;
        }
        else {
            die "Expected keys is either CODE REF|ARRAY REF";
        }

        my @mapped_keys = ();

        foreach my $my_alias(@events_keys) {
            my $setting = $data->{$my_alias} || $my_alias;

            if (ref $setting eq 'HASH') {
                push @mapped_keys, $setting->{field_name};
            }
            else {
                push @mapped_keys, $setting;
            }
        }

        $events->{keys} = sub { @mapped_keys };
    }

    my $debug = $self->$method($path, \%mapped_data, $headers ||= {}, $events ||= {});

    if ($events->{test_request_object}) {
        return $debug;
    }

    my $resp = $self->json_response;

    if (my $key = $resp_spec->{key}) {
        $resp = $resp->{$key};
    }

    my $row_spec = $resp_spec->{row};

    my $response_attr = sub {
        my ($row) = @_;
        my %mapped_row;
        my @other_keys = @{$row_spec->{_others} || []};
        while (my ($my_alias, $from_exchange) = each %$row_spec) {
            next if $my_alias =~ m/^_/;
            my $attr = $row->{$from_exchange};
            my $attr_func = "response_attr_$my_alias";
            if ($self->can($attr_func)) {
                $attr = $self->$attr_func($attr);
            }
            $mapped_row{$my_alias} = $attr;
        }
        foreach my $key(@other_keys) {
            my $attr = $row->{$key};
            my $attr_func = "response_attr_$key";
            if ($self->can($attr_func)) {
                $attr = $self->$attr_func($attr);
            }
            $mapped_row{_others}{$key} = $attr;
        }
        return %mapped_row;
    };

    if (ref $resp eq 'ARRAY') {
        my @mapped_rows;
        foreach my $row(@$resp) {
            my %mapped_row = $response_attr->($row);
            if (my $filter = $resp_spec->{row_filter}) {
                my $action = $self->$filter(\%mapped_row) || '';
                if ($action && $action !~ m/^(next|last)$/) {
                    die "Row Filter returns expected either 'next' or 'last' or '' or undef";
                }
                if ($action eq 'next') {
                    next;
                }
                elsif ($action eq 'last') {
                    last;
                }
            }
            push @mapped_rows, \%mapped_row;
        }

        if (my $sort = $resp_spec->{sort}) {
            @mapped_rows = sort { $self->$sort($a, $b) } @mapped_rows;
        }

        if (my $primary_key = $resp_spec->{array2hash}) {
            my %mapped_rows = map { $_->{$primary_key} => $_ } @mapped_rows;
            if (my $code = $resp_spec->{post_row}) {
                map { $self->$code($_, \%mapped_rows) } @mapped_rows;
            }
            return \%mapped_rows;
        }
        elsif (my $pri_key = $resp_spec->{'array2[hash]'}) {
            my %mapped_rows = ();
            foreach my $row(@mapped_rows) {
                push @{$mapped_rows{$row->{$pri_key}} ||= []}, $row;
            }

            if (my $sort = $resp_spec->{'array2[hash.sort]'}) {
                foreach my $list(values %mapped_rows) {
                    @$list = sort { $self->$sort($a, $b) } @$list;
                }
            }

            if (my $code = $resp_spec->{post_row}) {
                map { $self->$code($_, \%mapped_rows) } @mapped_rows;
            }
            return \%mapped_rows;
        }
        elsif (my $code = $resp_spec->{post_row}) {
            map { $self->$code($_, \@mapped_rows) } @mapped_rows;
        }

        return \@mapped_rows;
    }
    else {
        my %mapped_row = $response_attr->($resp);

        if (my $code = $resp_spec->{post_row}) {
            $self->$code(\%mapped_row);
        }

        return \%mapped_row;
    }
}

sub DEMOLISH {}

no Moo;

1;
