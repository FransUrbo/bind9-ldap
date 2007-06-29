#!/usr/bin/perl

# Copyright (C) 2005 Roman A.Egorov <rigel@atao.taimyr.ru>

# Permission to use, copy, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.

# $Id: zone2ldif.pl,v 1.3 2007-06-29 21:29:03 turbo Exp $

print( "zone2ldif: The converter of files of zones DNS in the file of a LDIFF format.\n" );
print( "           Version 1.01 (C) 2005 Roman A.Egorov <rigel\@atao.taimyr.ru>.\n" );
$err = 0;
$na = @ARGV;
$ldif = "";
if( $na > 6 )
{
    $err = 1;
    print( "ERROR: It is too much parameters.\n" );
}
else
{
    for( $i = 0; $i < $na/2; $i++ )
    {
	if( $ARGV[0] eq "-z" )
	{
	    shift( @ARGV );
	    $file = $ARGV[0];
	    shift( @ARGV );
	}
	elsif( $ARGV[0] eq "-b" )
	{
	    shift( @ARGV );
	    $basedn = $ARGV[0];
	    shift( @ARGV );
	}
	elsif( $ARGV[0] eq "-l" )
	{
	    shift( @ARGV );
	    $ldif = $ARGV[0];
	    shift( @ARGV );
	}
	elsif( ( $ARGV[0] eq "-h" ) || ( $ARGV[0] eq "--help" ) )
	{
	    $err = -1;
	    last;
	}
	else
	{
	    $err = 2;
	    print( "ERROR: Invalid parameter $ARGV[0].\n" );
	    last;
	}
    }
}
if( ( !($file) || !($basedn) ) && ( $err == 0 ) )
{
    $err = 3;
    print( "ERROR: Invalid parameters.\n" );
}
if( $err != 0 )
{
    print( "Usage:\n" );
    print( "zone2ldif -b DNS_DN -z ZONE_FILE_NAME [-l LDIF_FILE_NAME]\n" );
    print( "  -b DNS_DN		  DNS DN of a LDAP tree.\n" );
    print( "  -z ZONE_FILE_NAME	  Input DNS zones file.\n" );
    print( "  -l LDIF_FILE_NAME	  Output ldiff file.\n" );
    print( "  -h --help		  This message.\n" );
    exit( $err );
}
if( !$ldif )
{
    $ldif = "$file.ldif";
}
$ttl = "3600";
@azon = ();
if( !open( FZ, $file ) )
{
    print( "ERROR: Cannot open file $file !\n" );
    exit( 4 );
}
if( !open( FL, ">$ldif" ) )
{
    print( "ERROR: Cannot create file $ldif !\n" );
    exit( 5 );
}
@fz = <FZ>;
$nn = 0;
$ne = @fz;
while( $nn < $ne )
{
    $str = $fz[$nn];
    chomp( $str );
    $str = ( split( /;/, $str ) )[0];
    if( $str )
    {
	@fl = split( /\s+/, $str );
	if( $fl[0] eq "\$TTL" )
	{
	    $ttl = $fl[1];
	}
	elsif( $fl[0] eq "\$ORIGIN" )
	{
	    $zone = substr( $fl[1], 0, -1 );
	    $found = 0;
	    foreach $i ( @azon )
	    {
		if( $i eq $zone )
		{
		    $found++;
		}
	    }
	    if( !$found )
	    {
		print FL "\ndn: zoneName=$zone,$basedn\n";
	        print FL "objectClass: top\n";
		print FL "objectClass: dNSZone\n";
	        print FL "relativeDomainName: $zone\n";
		print FL "zoneName: $zone\n";
		push( @azon, $zone );
	    }
	}
	elsif( !$fl[0] )
	{
	    shift( @fl );
	    if( $fl[0] eq "IN" )
	    {
		shift( @fl );
	    }
	    $rec = $fl[0]."Record: ";
	    shift( @fl );
	    $rec = $rec.join( " ", @fl );
	    print FL "$rec\n";
	}
	else
	{
	    $name = $fl[0];
	    shift( @fl );
	    $lttl = "";
	    if( $fl[0] =~ /\b\d/ )
	    {
		$lttl = $fl[0];
		shift( @fl );
	    }
	    if( $fl[0] eq "IN" )
	    {
		shift( @fl );
	    }
	    $type = $fl[0];
	    shift( @fl );
	    if( $type eq "SOA" )
	    {
		$str = join( " ", @fl );
		@fl = split( /\(/, $str );
		@num = split( /\)/, $fl[1] );
		@num = split( /\s+/, $num[0] );
		if( !$num[0] )
		{
		    shift( @num );
		}
		$ff = @num;
		if( $ff > 5 )
		{
		    print( "ERROR: Bad zone file $file !\n" );
		    exit( 6 );
		}
		if( !( $fl[1] =~ /\)/ ) )
		{
		    do
		    {
			$nn++;
			$str = $fz[$nn];
			chomp( $str );
		        $str = ( split( /;/, $str ) )[0];
			if( $str )
			{
			    @tmp = split( /\)/, $str );
			    @tmp = split( /\s+/, $tmp[0] );
			    if( !$tmp[0] )
			    {
				shift( @tmp );
			    }
			    $ff += @tmp;
			    push( @num, @tmp );
			    if( $ff > 5 )
			    {
				print( "ERROR: Bad zone file $file !\n" );
				exit( 6 );
			    }
			}
		    }until( $str =~ /\)/ );
		}
		$str = $fl[0].join( " ", @num );
		@fl = split( /\s+/, $str );
	    }
	    $str = join( " ", @fl );
	    print FL "\ndn: relativeDomainName=$name,zoneName=$zone,$basedn\n";
	    print FL "objectClass: top\n";
	    print FL "objectClass: dNSZone\n";
	    print FL "relativeDomainName: $name\n";
	    print FL "zoneName: $zone\n";
	    if( $lttl )
	    {
		print FL "dNSTTL: $lttl\n";
	    }
	    else
	    {
		print FL "dNSTTL: $ttl\n";
	    }
	    print FL "dNSClass: IN\n";
	    print FL $type."Record: $str\n";
	}
    }
    $nn++;
}
close( FZ );
close( FL );
print( "The converting from $file in $ldif is completed successfully.\n" );
