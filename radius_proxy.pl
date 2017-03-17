###########################################################################################
#
# RADIUS PROXY OPENSCRIPT
#
# AUTHOR: Tim Braly   tbraly@brocade.com
#
# Version 1.0
#
# THIS SCRIPT IS USEFUL TO REDIRECT RADIUS PACKETS TO SPECIFIC SERVER GROUPS BASED ON
# VALUES IN THE PACKET
#
###########################################################################################
use OS_IP;
use OS_UDP;
use OS_SLB;
use strict;
my ($RADIUS_START_OF_TLV, $RADIUS_TYPECODE_USERNAME, $RADIUS_TYPECODE_VENDOR_SPECIFIC);
sub BEGIN {
    $RADIUS_START_OF_TLV = 20;
    $RADIUS_TYPECODE_USERNAME = 1;
    $RADIUS_TYPECODE_VENDOR_SPECIFIC = 26;
}
sub UDP_CLIENT_DATA {
    ####################################################################################
    #
    # Extract all TLV's from Radius Packet and store in a hash table with the 'type' as
    # the hash key.
    #
    # Vendor Specific Values will be stored as 'vendor_code-type' as the hash key.
    #
    ####################################################################################
    my $udp_data = OS_UDP::Payload;
    my %tlv = ();
    my $i = $RADIUS_START_OF_TLV;
    while ($i < length($udp_data)) {
        my $type = ord(substr($udp_data,$i++,1));
        my $length = ord(substr($udp_data,$i++,1));
        my $type_data = "";
        if($type == $RADIUS_TYPECODE_VENDOR_SPECIFIC) {
            my $vendor_code = hex sprintf("0x%s",unpack("H*",substr($udp_data,$i,4)));
            $type = sprintf "%d-%d",$vendor_code,ord(substr($udp_data,$i+4,1));
            $i = $i + 5;
            $length = ord(substr($udp_data,$i++,1)); 
            $type_data = substr($udp_data,$i,$length-2);
        } else {
            $type_data = substr($udp_data,$i,$length-2);
        }
        $tlv{$type} = $type_data;
        $i+=$length-2;
        if($length < 2) {
            # This is bad condition and can create an infinent loop, so exit
            print "Malformed packet detected\n";
            $i = length($udp_data); # This will exit the loop
            %tlv = (); # Erase what already learned
        }
    }
    ####################################################################################
    #
    # Grab Authenication Username and based on domain, forward to a server groups
    # See RFC 2865 and updates for Attribute Type Values
    #
    ####################################################################################
    my $username = $tlv{$RADIUS_TYPECODE_USERNAME};
    if ($username =~ /\@domain/ ) {
        # Forward to Radius Server A
        print "Forwarding radius packet for user '$username' to Radius Server A\n";
        OS_SLB::forward(1);
    } else {
        # Forward to Radius Server B
        print "Forwarding radius packet for user '$username' to Radius Server B\n";
        OS_SLB::forward(2);
    }
}
