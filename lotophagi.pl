# Lotophagi
# Lotus Notes default Database discovery tool 

# Mostly ripped off from CGIVTI by Lawrence Lavigne
# 2007, Michael Kemp .:clappymonkey:.  

# Lotophagi quickly scans a host (or IP) as specified in an input file for default Lotus Notes database instances

# Any comments or bugs, please mail clappymonkey'at'gmail'dot'com  


use strict;
use LWP::UserAgent;
use HTTP::Request;
use HTTP::Response;

my $def = new LWP::UserAgent;
my @victim;
my $userresp;

print<<__MENU;
*********************************
*                               *
*          Lotophagi            * 
*	                        *
*    Default Database Scanner   *
*                               *
*       .:clappymonkey:.        * 
*  http://www.clappymonkey.com  *
*                               * 
*********************************
               
__MENU



print qq(\n\n\nCheck your box? [Y/N]: );
while(1) {
        chomp($userresp = <STDIN>);
        if($userresp eq "Y" || $userresp eq "y" || $userresp eq "yes") {
                print "Here goes nothing...\n";
                last;
        } elsif($userresp eq "N" || $userresp eq "n" || $userresp eq "no") {
                print "Right then - ciao.\n";
		exit;
        } else {
                print "Yes or No... it is that hard? [Y/N]: ";
        }
}
print qq(\nWhat file contains the victim address: );

chomp(my $victim=<STDIN>);
open(IN, $victim) || die "\nCould not open $victim: $!"; 
while (<IN>) 
{ 
	$victim[$a] = $_; 
	chomp $victim[$a]; 
	$a++; 
        $b++; 
} 
close(IN);
$a = 0; 
print qq(Scan Initiated..\n\n);
while ($a < $b) 
{ 
    print qq(:: Checking for /statrep.nsf\n);
	my $url="http://$victim[$a]/statrep.nsf";
	my $request = new HTTP::Request('GET', $url);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The statrep.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The statrep.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&second()
	} 
sub second() {
    print qq(:: Checking for /schema.nsf\n);
	my $url2="http://$victim[$a]/schema.nsf";
	my $request = new HTTP::Request('GET', $url2);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The schema.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The schema.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	} 
	&third()
	}
sub third() {
    print qq(:: Checking for /reports.nsf\n);
	my $url3="http://$victim[$a]/reports.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The reports.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The reports.nsf Database is enabled (allegedly). Go check.\n\n";  
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fourth()
	}
sub fourth() {
    print qq(:: Checking for /names.nsf\n);
	my $url3="http://$victim[$a]/names.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The names.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The names.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fifth()
	}
sub fifth() {
    print qq(:: Checking for /log.nsf\n);
	my $url3="http://$victim[$a]/log.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The log.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The log.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}	
	&sixth()
	}
sub sixth() {
    print qq(:: Checking for /events4.nsf\n);
	my $url3="http://$victim[$a]/events4.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The events4.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The events4.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&seventh()
	}
sub seventh() {
    print qq(:: Checking for /doladmin.nsf\n);
	my $url3="http://$victim[$a]/doladmin.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The doladmin.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The doladmin.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&eigth()
	}
sub eigth() {
    print qq(:: Checking for /dbdirman.nsf\n);
	my $url3="http://$victim[$a]/dbdirman.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The dbdirman.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The dbdirman.nsf Database is enabled (allegedly). Go check.\n\n";  
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&nine()
	}
sub nine() {
    print qq(:: Checking for /certsrv.nsf\n);
	my $url3="http://$victim[$a]/certsrv.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The certsrv.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The certsrv.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&ten()
	}
sub ten() {
    print qq(:: Checking for /certlog.nsf\n);
	my $url3="http://$victim[$a]/certlog.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The certlog.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The certlog.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&eleven()
	}
sub eleven() {
    print qq(:: Checking for /852566C90012664F/\n);
	my $url3="http://$victim[$a]/852566C90012664F/";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The 852566C90012664F Database is enabled (allegedly). "; 
	-close OUT;
print "The 852566C90012664F Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&twelth()
	}
sub twelth() {
    print qq(:: Checking for /admin4.nsf\n);
	my $url3="http://$victim[$a]/admin4.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The admin4.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The admin4.nsf Database is enabled (allegedly). Go check.\n\n";  
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&thirteenth()
	}
sub thirteenth() {
    print qq(:: Checking for /admin5.nsf\n);
	my $url3="http://$victim[$a]/admin5.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The admin5.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The admin5.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fourteenth()
	}
sub fourteenth() {
    print qq(:: Checking for /agentrunner.nsf\n);
	my $url3="http://$victim[$a]/agentrunner.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The agentrunner.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The agentrunner.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fifteenth()
	}
sub fifteenth() {
    print qq(:: Checking for /alog.nsf\n);
	my $url3="http://$victim[$a]/alog.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
	open(OUT, ">>results.log"); 
	print OUT "The alog.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The alog.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&sixteenth()
	}
sub sixteenth() {
    print qq(:: Checking for /a_domlog.nsf\n);
	my $url3="http://$victim[$a]/a_domlog.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The a_domlog.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The a_domlog.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&seventeenth()
	}
sub seventeenth() {
    print qq(:: Checking for /bookmark.nsf\n);
	my $url3="http://$victim[$a]/bookmark.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The bookmark.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The bookmark.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&eighteenth()
	}
sub eighteenth() {
    print qq(:: Checking for /busytime.nsf\n);
	my $url3="http://$victim[$a]/busytime.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The busytime.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The busytime.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}	
	&nineteenth()
	}
sub nineteenth() {
    print qq(:: Checking for /catalog.nsf\n);
	my $url3="http://$victim[$a]/catalog.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The catalog.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The catalog.nsf Database is enabled (allegedly). Go check.\n\n";  
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&twentieth()
	}
sub twentieth() {
    print qq(:: Checking for /chatlog.nsf\n);
	my $url3="http://$victim[$a]/chatlog.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The chatlog.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The chatlog.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&twentyfirst()
	}
sub twentyfirst() {
    print qq(:: Checking for /clbusy.nsf\n);
	my $url3="http://$victim[$a]/clbusy.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The clbusy.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The clbusy.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&twentysecond()
	}
sub twentysecond() {
    print qq(:: Checking for /cldbdir.nsf\n);
	my $url3="http://$victim[$a]/cldbdir.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The cldbdir.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The cldbdir.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&twentythird()
	}
sub twentythird() {
    print qq(:: Checking for /clusta4.nsf\n);
	my $url3="http://$victim[$a]/clusta4.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The clusta4.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The clusta4.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&twentyfourth()
	}
sub twentyfourth() {
    print qq(:: Checking for /collect4.nsf\n);
	my $url3="http://$victim[$a]/collect4.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The collect4.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The collect4.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&twentyfifth()
	}
sub twentyfifth() {
    print qq(:: Checking for /da.nsf\n);
	my $url3="http://$victim[$a]/da.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The da.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The da.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&twentysixth()
	}
sub twentysixth() {
    print qq(:: Checking for /dba4.nsf\n);
	my $url3="http://$victim[$a]/dba4.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The dba4.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The dba4.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&twentyseventh()
	}
sub twentyseventh() {
    print qq(:: Checking for /dclf.nsf\n);
	my $url3="http://$victim[$a]/dclf.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The dclf.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The dclf.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&twentyeighth()
	}
sub twentyeighth() {
    print qq(:: Checking for /DEASAppDesign.nsf\n);
	my $url3="http://$victim[$a]/DEASAppDesign.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The DEASAppDesign.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The DEASAppDesign.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&twentyninth()
	}
sub twentyninth() {
    print qq(:: Checking for /DEASLog01.nsf\n);
	my $url3="http://$victim[$a]/DEASLog01.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The DEASLog01.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The DEASLog01.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&thirtieth()
	}
sub thirtieth() {
    print qq(:: Checking for /DEASLog02.nsf\n);
	my $url3="http://$victim[$a]/DEASLog02.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The DEASLog02.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The DEASLog02.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&thirtyfirst()
	}
sub thirtyfirst() {
    print qq(:: Checking for /DEASLog03.nsf\n);
	my $url3="http://$victim[$a]/DEASLog03.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The DEASLog03.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The DEASLog03.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&thirtysecond()
	}
sub thirtysecond() {
    print qq(:: Checking for /DEASLog04.nsf\n);
	my $url3="http://$victim[$a]/DEASLog04.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The DEASLog04.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The DEASLog04.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&thirtythird()
	}
sub thirtythird() {
    print qq(:: Checking for /DEASLog05.nsf\n);
	my $url3="http://$victim[$a]/DEASLog05.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The DEASLog05.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The DEASLog05.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&thirtyfourth()
	}
sub thirtyfourth() {
    print qq(:: Checking for /DEASLog.nsf\n);
	my $url3="http://$victim[$a]/DEASLog.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The DEASLog.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The DEASLog.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&thirtyfifth()
	}
sub thirtyfifth() {
    print qq(:: Checking for /decsadm.nsf\n);
	my $url3="http://$victim[$a]/decsadm.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The decsadm.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The decsadm.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&thirtysixth()
	}
sub thirtysixth() {
    print qq(:: Checking for /decslog.nsf\n);
	my $url3="http://$victim[$a]/decslog.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The decslog.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The decslog.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&thirtyseventh()
	}
sub thirtyseventh() {
    print qq(:: Checking for /DEESAdmin.nsf\n);
	my $url3="http://$victim[$a]/DEESAdmin.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The DEESAdmin.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The DEESAdmin.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&thirtyeighth()
	}
sub thirtyeighth() {
    print qq(:: Checking for /dirassist.nsf\n);
	my $url3="http://$victim[$a]/dirassist.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The dirassist.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The dirassist.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&thirtyninth()
	}
sub thirtyninth() {
    print qq(:: Checking for /domadmin.nsf\n);
	my $url3="http://$victim[$a]/domadmin.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The domadmin.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The domadmin.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fourtieth()
	}
sub fourtieth() {
    print qq(:: Checking for /domcfg.nsf\n);
	my $url3="http://$victim[$a]/domcfg.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The domcfg.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The domcfg.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fourtyfirst()
	}
sub fourtyfirst() {
    print qq(:: Checking for /domguide.nsf\n);
	my $url3="http://$victim[$a]/domguide.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The domguide.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The domguide.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fourtysecond()
	}
sub fourtysecond() {
    print qq(:: Checking for /domlog.nsf\n);
	my $url3="http://$victim[$a]/domlog.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The domlog.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The domlog.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fourtythird()
	}
sub fourtythird() {
    print qq(:: Checking for /dspug.nsf\n);
	my $url3="http://$victim[$a]/dspug.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The dspug.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The dspug.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fourtyfourth()
	}
sub fourtyfourth() {
    print qq(:: Checking for /events5.nsf\n);
	my $url3="http://$victim[$a]/events5.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The events5.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The events5.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fourtyfifth()
	}
sub fourtyfifth() {
    print qq(:: Checking for /events.nsf\n);
	my $url3="http://$victim[$a]/events.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The events.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The events.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fourtysixth()
	}
sub fourtysixth() {
    print qq(:: Checking for /event.nsf\n);
	my $url3="http://$victim[$a]/event.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The event.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The event.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fourtyseven()
	}
sub fourtyseven() {
    print qq(:: Checking for /homepage.nsf\n);
	my $url3="http://$victim[$a]/homepage.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The homepage.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The homepage.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fourtyeight()
	}
sub fourtyeight() {
    print qq(:: Checking for /iNotes/Forms5.nsf\n);
	my $url3="http://$victim[$a]/iNotes/Forms5.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The iNotes/Forms5.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The iNotes/Forms5.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fourtynine()
	}
sub fourtynine() {
    print qq(:: Checking for jotter.nsf\n);
	my $url3="http://$victim[$a]/jotter.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The jotter.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The jotter.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fifty()
	}
sub fifty() {
    print qq(:: Checking for leiadm.nsf\n);
	my $url3="http://$victim[$a]/leiadm.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The leiadm.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The leiadm.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fiftyone()
	}
sub fiftyone() {
    print qq(:: Checking for leilog.nsf\n);
	my $url3="http://$victim[$a]/leilog.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The leilog.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The leilog.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fiftytwo()
	}
sub fiftytwo() {
    print qq(:: Checking for leivlt.nsf\n);
	my $url3="http://$victim[$a]/leivlt.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The leivlt.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The leivlt.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fiftythree()
	}
sub fiftythree() {
    print qq(:: Checking for log4a.nsf\n);
	my $url3="http://$victim[$a]/log4a.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The log4a.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The log4a.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fiftyfour()
	}
sub fiftyfour() {
    print qq(:: Checking for l_domlog.nsf\n);
	my $url3="http://$victim[$a]/l_domlog.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The l_domlog.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The l_domlog.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fiftyfive()
	}
sub fiftyfive() {
    print qq(:: Checking for mab.nsf\n);
	my $url3="http://$victim[$a]/mab.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The mab.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The mab.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fiftysix()
	}
sub fiftysix() {
    print qq(:: Checking for mail.box\n);
	my $url3="http://$victim[$a]/mail.box";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The mail.box Database is enabled (allegedly). "; 
	-close OUT;
print "The mail.box Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fiftyseven()
	}
sub fiftyseven() {
    print qq(:: Checking for mail1.box\n);
	my $url3="http://$victim[$a]/mail1.box";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The mail1.box Database is enabled (allegedly). "; 
	-close OUT;
print "The mail1.box Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fiftyeight()
	}
sub fiftyeight() {
    print qq(:: Checking for mail2.box\n);
	my $url3="http://$victim[$a]/mail2.box";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The mail2.box Database is enabled (allegedly). "; 
	-close OUT;
print "The mail2.box Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&fiftynine()
	}
sub fiftynine() {
    print qq(:: Checking for mail3.box\n);
	my $url3="http://$victim[$a]/mail3.box";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The mail3.box Database is enabled (allegedly). "; 
	-close OUT;
print "The mail3.box Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&sixty()
	}
sub sixty() {
    print qq(:: Checking for mail4.box\n);
	my $url3="http://$victim[$a]/mail4.box";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The mail4.box Database is enabled (allegedly). "; 
	-close OUT;
print "The mail4.box Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&sixtyone()
	}
sub sixtyone() {
    print qq(:: Checking for mail5.box\n);
	my $url3="http://$victim[$a]/mail5.box";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The mail5.box Database is enabled (allegedly). "; 
	-close OUT;
print "The mail5.box Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&sixtytwo()
	}
sub sixtytwo() {
    print qq(:: Checking for mail6.box\n);
	my $url3="http://$victim[$a]/mail6.box";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The mail6.box Database is enabled (allegedly). "; 
	-close OUT;
print "The mail6.box Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&sixtythree()
	}
sub sixtythree() {
    print qq(:: Checking for mail7.box\n);
	my $url3="http://$victim[$a]/mail7.box";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The mail7.box Database is enabled (allegedly). "; 
	-close OUT;
print "The mail7.box Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&sixtyfour()
	}
sub sixtyfour() {
    print qq(:: Checking for mail8.box\n);
	my $url3="http://$victim[$a]/mail8.box";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The mail8.box Database is enabled (allegedly). "; 
	-close OUT;
print "The mail8.box Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&sixtyfive()
	}
sub sixtyfive() {
    print qq(:: Checking for mail9.box\n);
	my $url3="http://$victim[$a]/mail9.box";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The mail9.box Database is enabled (allegedly). "; 
	-close OUT;
print "The mail9.box Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&sixtysix()
	}
sub sixtysix() {
    print qq(:: Checking for mail10.box\n);
	my $url3="http://$victim[$a]/mail10.box";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The mail10.box Database is enabled (allegedly). "; 
	-close OUT;
print "The mail10.box Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&sixtyseven()
	}
sub sixtyseven() {
    print qq(:: Checking for msdwda.nsf\n);
	my $url3="http://$victim[$a]/msdwda.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The msdwda.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The msdwda.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&sixtyeight()
	}
sub sixtyeight() {
    print qq(:: Checking for mtatbls.nsf\n);
	my $url3="http://$victim[$a]/mtatbls.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The mtatbls.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The mtatbls.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&sixtynine()
	}
sub sixtynine() {
    print qq(:: Checking for mtstore.nsf\n);
	my $url3="http://$victim[$a]/mtstore.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The mtstore.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The mtstore.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&seventy()
	}
sub seventy() {
    print qq(:: Checking for nntppost.nsf\n);
	my $url3="http://$victim[$a]/nntppost.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The nntppost.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The nntppost.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&seventyone()
	}
sub seventyone() {
    print qq(:: Checking for nntp/nd000001.nsf\n);
	my $url3="http://$victim[$a]/nntp/nd000001.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The nntp/nd000001.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The nntp/nd000001.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&seventytwo
	}
sub seventytwo() {
    print qq(:: Checking for nntp/nd000002.nsf\n);
	my $url3="http://$victim[$a]/nntp/nd000002.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The nntp/nd000002.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The nntp/nd000002.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&seventythree()
	}
sub seventythree() {
    print qq(:: Checking for nntp/nd000003.nsf\n);
	my $url3="http://$victim[$a]/nntp/nd000003.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The nntp/nd000003.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The nntp/nd000003.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&seventyfour
	}
sub seventyfour() {
    print qq(:: Checking for ntsync45.nsf\n);
	my $url3="http://$victim[$a]/ntsync45.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The ntsync45.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The ntsync45.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}	
	&seventyfive
	}
sub seventyfive() {
    print qq(:: Checking for perweb.nsf\n);
	my $url3="http://$victim[$a]/perweb.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The perweb.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The perweb.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}	
	&seventysix()
	}
sub seventysix() {
    print qq(:: Checking for qpadmin.nsf\n);
	my $url3="http://$victim[$a]/qpadmin.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The qpadmin.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The qpadmin.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}	
	&seventyseven()
	}
sub seventyseven() {
    print qq(:: Checking for quickplace/quickplace/main.nsf\n);
	my $url3="http://$victim[$a]/quickplace/quickplace/main.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The quickplace/quickplace/main.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The quickplace/quickplace/main.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}	
	&seventyeight()
	}
sub seventyeight() {
    print qq(:: Checking for sample/siregw46.nsf\n);
	my $url3="http://$victim[$a]/sample/siregw46.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The sample/siregw46.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The sample/siregw46.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&seventynine()
	}
sub seventynine() {
    print qq(:: Checking for schema50.nsf\n);
	my $url3="http://$victim[$a]/schema50.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The schema50.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The schema50.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&eighty()
	}
sub eighty() {
    print qq(:: Checking for setupweb.nsf\n);
	my $url3="http://$victim[$a]/setupweb.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The setupweb.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The setupweb.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&eightyone()
	}
sub eightyone() {
    print qq(:: Checking for setup.nsf\n);
	my $url3="http://$victim[$a]/setup.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The setup.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The setup.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&eightytwo()
	}
sub eightytwo() {
    print qq(:: Checking for smbcfg.nsf\n);
	my $url3="http://$victim[$a]/smbcfg.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The smbcfg.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The smbcfg.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&eightythree()
	}
sub eightythree() {
    print qq(:: Checking for smconf.nsf\n);
	my $url3="http://$victim[$a]/smconf.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The smconf.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The smconf.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&eightyfour()
	}
sub eightyfour() {
    print qq(:: Checking for smency.nsf\n);
	my $url3="http://$victim[$a]/smency.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The smency.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The smency.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&eightyfive()
	}
sub eightyfive() {
    print qq(:: Checking for smhelp.nsf\n);
	my $url3="http://$victim[$a]/smhelp.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The smhelp.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The smhelp.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&eightysix()
	}
sub eightysix() {
    print qq(:: Checking for smmsg.nsf\n);
	my $url3="http://$victim[$a]/smmsg.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The smmsg.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The smmsg.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&eightyseven()
	}
sub eightyseven() {
    print qq(:: Checking for smquar.nsf\n);
	my $url3="http://$victim[$a]/smquar.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The smquar.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The smquar.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&eightyeight()
	}
sub eightyeight() {
    print qq(:: Checking for smsolar.nsf\n);
	my $url3="http://$victim[$a]/smsolar.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The smsolar.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The smsolar.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&eightynine()
	}
sub eightynine() {
    print qq(:: Checking for smtime.nsf\n);
	my $url3="http://$victim[$a]/smtime.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The smtime.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The smtime.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&ninety()
	}
sub ninety() {
    print qq(:: Checking for smtpibwq.nsf\n);
	my $url3="http://$victim[$a]/smtpibwq.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The smtpibwq.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The smtpibwq.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&ninetyone()
	}
sub ninetyone() {
    print qq(:: Checking for smtpobwq.nsf\n);
	my $url3="http://$victim[$a]/smtpobwq.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The smtpobwq.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The smtpobwq.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&ninetytwo()
	}
sub ninetytwo() {
    print qq(:: Checking for smtp.box\n);
	my $url3="http://$victim[$a]/smtp.box";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The smtp.box Database is enabled (allegedly). "; 
	-close OUT;
print "The smtp.box Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&ninetythree()
	}
sub ninetythree() {
    print qq(:: Checking for smtp.nsf\n);
	my $url3="http://$victim[$a]/smtp.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The smtp.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The smtp.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&ninetyfour()
	}
sub ninetyfour() {
    print qq(:: Checking for smvlog.nsf\n);
	my $url3="http://$victim[$a]/smvlog.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The smvlog.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The smvlog.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&ninetyfive()
	}
sub ninetyfive() {
    print qq(:: Checking for srvnam.nsf\n);
	my $url3="http://$victim[$a]/srvnam.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The srvnam.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The srvnam.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&ninetysix()
	}
sub ninetysix() {
    print qq(:: Checking for statmail.nsf\n);
	my $url3="http://$victim[$a]/statmail.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The statmail.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The statmail.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&ninetyseven()
	}
sub ninetyseven() {
    print qq(:: Checking for statrep.nsf\n);
	my $url3="http://$victim[$a]/statrep.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The statrep.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The statrep.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&ninetyeight()
	}
sub ninetyeight() {
    print qq(:: Checking for stauths.nsf\n);
	my $url3="http://$victim[$a]/stauths.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The stauths.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The stauths.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&ninetynine()
	}
sub ninetynine() {
    print qq(:: Checking for stautht.nsf\n);
	my $url3="http://$victim[$a]/stautht.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The stautht.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The stautht.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&onehundred()
	}
sub onehundred() {
    print qq(:: Checking for stconfig.nsf\n);
	my $url3="http://$victim[$a]/stconfig.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The stconfig.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The stconfig.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&onehundredandone()
	}
sub onehundredandone() {
    print qq(:: Checking for stconf.nsf\n);
	my $url3="http://$victim[$a]/stconf.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The stconf.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The stconf.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&onehundredandtwo()
	}
sub onehundredandtwo() {
    print qq(:: Checking for stdnaset.nsf\n);
	my $url3="http://$victim[$a]/stdnaset.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The stdnaset.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The stdnaset.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&onehundredandthree()
	}
sub onehundredandthree() {
    print qq(:: Checking for stdomino.nsf\n);
	my $url3="http://$victim[$a]/stdomino.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The stdomino.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The stdomino.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&onehundredandfour()
	}
sub onehundredandfour() {
    print qq(:: Checking for stlog.nsf\n);
	my $url3="http://$victim[$a]/stlog.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The stlog.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The stlog.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&onehundredandfive()
	}
sub onehundredandfive() {
    print qq(:: Checking for streg.nsf\n);
	my $url3="http://$victim[$a]/streg.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The streg.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The streg.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&onehundredandsix()
	}
sub onehundredandsix() {
    print qq(:: Checking for stsrc.nsf\n);
	my $url3="http://$victim[$a]/stsrc.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The stsrc.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The stsrc.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&onehundredandseven()
	}
sub onehundredandseven() {
    print qq(:: Checking for userreg.nsf\n);
	my $url3="http://$victim[$a]/userreg.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The userreg.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The userreg.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&onehundredandeight()
	}
sub onehundredandeight() {
    print qq(:: Checking for vpuserinfo.nsf\n);
	my $url3="http://$victim[$a]/vpuserinfo.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The vpuserinfo.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The vpuserinfo.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&onehundredandnine()
	}
sub onehundredandnine() {
    print qq(:: Checking for webadmin.nsf\n);
	my $url3="http://$victim[$a]/webadmin.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The webadmin.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The webadmin.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
	&onehundredandten()
	}
sub onehundredandten() {
    print qq(:: Checking for web.nsf\n);
	my $url3="http://$victim[$a]/web.nsf";
	my $request = new HTTP::Request('GET', $url3);
	my $response = $def->request($request);
	if ($response->is_success) {
  	open(OUT, ">>results.log"); 
	print OUT "The web.nsf Database is enabled (allegedly). "; 
	-close OUT;
print "The web.nsf Database is enabled (allegedly). Go check.\n\n"; 
	} else { 
	print qq(Not Vulnerable...\n\n);
	}
print "Scan Complete...\n\n";
  	$a++;
  	}
exit;
  	<>   