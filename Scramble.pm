package PDF::Reuse::Scramble;

use 5.006;
use strict;
use warnings;
use integer;

require Exporter;

our @ISA = qw(Exporter);
our %EXPORT_TAGS = ( 'all' => [ qw(authorize encrypt decrypt) ] );
our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );
our $VERSION = '0.01';

sub authorize
{  my $User = shift || ' ';
   my $Pass = shift || ' ';
   my $seed = shift || time;
   srand($seed);
   my $random = uc(sprintf("%x",rand(999999)));
   $random   .= sprintf("%x",rand(999999));
   $random   .= uc(sprintf("%x",rand(999999)));
   $random   .= sprintf("%x",rand(999999));
   $random   .= uc(sprintf("%x",rand(999999)));
   while ((length($User) < 4) || (length($Pass) < 4))
   {   if (length($User) < 4)
       {  print "User     (at least 5 letters) : ";
          $User = <STDIN>;
          chomp($User);
       }
       if (length($Pass) < 4)
       {  print "Password (at least 5 letters) : ";
          $Pass = <STDIN>;
          chomp($Pass);
       }
   } 
   my $rest = 0;
   my $fullKey = '';
   my $matchKey = '';
   my $num2 = 17;
   my $rest2 = 0;
   my $corr = ord(substr($Pass, 0, 1)) + ord(substr($User, 0, 1));
   my $lr = length($random) - 1;
   my $k = $corr % $lr;
   my $lu = length($User) - 1;
   my $j = $corr % $lu;
   $corr = ($corr + ord(substr($random, $k, 1)) + $j + $k) % 37;
   for (my $i = 0; $i < length($Pass); $i++)
   {  my $num1 = ord(substr($Pass,$i,1)) + $corr;
      my $spar = $num1 % 53;
      $num1 += ($i < length($User)) ? ord(substr($User, $i, 1)) : $i ;
      my $num3 = ord(substr($random, $k, 1)) % 53;
      $num1 += ($spar > $num3 ) ? $num3 : ord(substr($random, $k, 1));
      $num2 += $num1 + $num3;
      $rest += $num1 % 77;
      $rest2 += $num2 % 109;
      $num1 *= 7;
      $num1 %= 46;
      $num2 *= 9;
      $num2 %= 46;
      $num1 *= 17;
      $num2 *= 13;
      $num1 %= 256;
      $num2 %= 256;        
      $fullKey .= sprintf("%x", $num1);
      $matchKey .= sprintf("%x", $num2);
      $num2 = $num1 % 98;
      $corr = ord(substr($Pass, $i, 1)) + ord(substr($User, $j, 1))
               + ord(substr($random, $k, 1)) + $i + $j + $k;
      $j = $corr % $lu;
      $k = $corr % $lr;
      $corr = $corr % 37;
  }
  $fullKey .= sprintf("%x", $rest);
  $matchKey .= sprintf("%x", $rest2);
  $fullKey = uc($fullKey);
  $matchKey = uc($matchKey);
  my $l = sprintf("%d",(length($fullKey) / 2));
  my $halfKey = substr($fullKey, 0, $l); 
  my $str = <<"EOF";
function authorize()
{ var chances = 0;
  scramble = '$random';
  while (chances < 3)
  { var User = app.response('',"Userid",'', true);
    var Pass = app.response('',"Password",'', true);
    var rest = 0;
    fullKey = '';
    var matchKey = '';
    var num2 = 17;
    var rest2 = 0;
    var corr = Pass.charCodeAt(0) + User.charCodeAt(0);
    var sl = scramble.length - 1;
    var k = corr % sl;
    var ul = User.length - 1;
    var j = corr % ul;
    corr = (corr + scramble.charCodeAt(k) + j + k) % 37;
    for (var i = 0; i < Pass.length; i++)
    { var num1 = Pass.charCodeAt(i) + corr;
      var spar = num1 % 53;
      num1 += (i < User.length) ? User.charCodeAt(i) : i;
      var num3 = scramble.charCodeAt(k) % 53;
      num1 += (spar > num3 ) ? num3 : scramble.charCodeAt(k);
      num2 += num1 + num3;
      rest += num1 % 77;
      rest2 += num2 % 109;
      num1 *= 7;
      num1 %= 46;
      num2 *= 9;
      num2 %= 46;
      num1 *= 17;
      num2 *= 13;
      num1 %= 256;
      num2 %= 256;
      fullKey += '' + util.printf("%x", num1);
      matchKey += '' + util.printf("%x", num2);        
      num2 = num1 % 98;
      corr = Pass.charCodeAt(i) + User.charCodeAt(j)
           + scramble.charCodeAt(k) + i + j + k;
      j = corr % ul;
      k = corr % sl;
      corr = corr % 37;
   }
   fullKey += '' + util.printf("%x", rest);
   var l = util.printf("%d",(fullKey.length / 2));
   halfKey = fullKey.slice(0, l);
   matchKey += '' + util.printf("%x", rest2);
   if (matchKey == '$matchKey')
     chances = 5;
   else
   {  halfKey = '';
      fullKey = '';
   }     
   chances++;
  }       
} 
function encrypt(word)
{ var key = fullKey;
  if ((! key) || (! word))
     return '';
  var j = Math.round(Math.random() * 8) + 1;
  var out = '%' + util.printf("%x", (j + 48));
  var sl = scramble.length - 1;
  var kl = key.length - 1;
  if ((kl) && (j > kl))
    j %= kl;
  var corr = key.charCodeAt(j);
  j = corr % kl;
  var k = corr % sl;
  corr = (corr + k + j) % 45;
  for (var i = 0; i < word.length; i++ )
  {  var num = word.charCodeAt(i) + corr;
     corr = key.charCodeAt(j) + scramble.charCodeAt(k) + i + j + k;
     num += corr % 23; 
     num += scramble.charCodeAt(k) % 19;
     out += '%' + util.printf("%x", num);
     if (j < 1)
       j = kl;
     else
       j--; 
     k = corr % sl;
     corr %= 45;
  }
  return out;
}
function decrypt(word)
{ var key = halfKey;
  var out = '';
  if ((! key) || (! word))
     return out;
  word = unescape(word);
  var j = word.charAt(0);
  word = word.substring(1);
  var sl = scramble.length - 1;
  var kl = key.length - 1;
  if ((kl) && (j > kl))
    j %= kl;
  var corr = key.charCodeAt(j);
  j = corr % kl;
  var k = corr % sl;
  corr = (corr + k + j) % 45;
  for (var i = 0; i < word.length; i++ )
  {  var num = word.charCodeAt(i) - corr;
     corr = key.charCodeAt(j) + scramble.charCodeAt(k) + i + j + k;
     num -= corr % 23; 
     num -= scramble.charCodeAt(k) % 19;
     out += '%' + util.printf("%x", num);
     if (j < 1)
       j = kl;
     else
       j--; 
     k = corr % sl;
     corr %= 45;
  }
  return unescape(out);
}

EOF
    
  return ($fullKey, $halfKey, $random, $str);
}

##############################################################
# To scramble and translate a string to a hex-encoded string 
##############################################################
sub encrypt
{  my ($word, $key, $scramble) = @_;
   return unless ($word) && ($key );
 
   my $j = rand(8) + 1;
   my $out = '%' . sprintf("%x", ord($j));
   my $lr = length($scramble) - 1;
   my $lh = length($key ) - 1;
       
   if (($lh) && ($j > $lh))
   { $j = $j % $lh;
   }

   my $corr = ord(substr($key , $j, 1));
   $j =  $corr % $lh;
   my $k = $corr % $lr;
   $corr = ($corr + $k + $j) % 45;

   my $num;    
   for (my $i = 0; $i < length($word); $i++ )
   {  $num  = ord(substr($word, $i, 1)) + $corr;
      $corr = ord(substr($key, $j, 1)) + ord(substr($scramble, $k, 1)) 
            + $i + $j + $k;
      $num += $corr % 23; 
      $num += ord(substr($scramble, $k, 1)) % 19;
      $out .= '%' . sprintf("%x", $num);
      if ($j < 1)
      {  $j = $lh; }
      else
      {  $j--;} 
      $k = $corr % $lr;
      $corr = $corr % 45;
   }
   return uc($out);
}

sub decrypt
{  my $out = '';
   my ($word, $key, $scramble) = @_;
   return unless ($word) && ($key );
   if ($word =~ m/^(%[0-9A-F]{2})+\&?$/gso)
   {  $word =~ s/%(..)/pack('c',hex($1))/eg;
   } 
   my $j = substr($word, 0, 1);
   $word = substr($word, 1);
   
   my $lr = length($scramble) - 1;
   my $lh = length($key ) - 1;
       
   if (($lh) && ($j > $lh))
   { $j = $j % $lh;
   }

   my $corr = ord(substr($key , $j, 1));
   $j =  $corr % $lh;
   my $k = $corr % $lr;
   $corr = ($corr + $k + $j) % 45;

   my $num;    
   for (my $i = 0; $i < length($word); $i++ )
   {  $num  = ord(substr($word, $i, 1)) - $corr;
      $corr = ord(substr($key, $j, 1)) + ord(substr($scramble, $k, 1)) 
            + $i + $j + $k;
      $num -= $corr % 23; 
      $num -= ord(substr($scramble, $k, 1)) % 19;
      $out .= chr($num);
      if ($j < 1)
      {  $j = $lh; }
      else
      {  $j--;} 
      $k = $corr % $lr;
      $corr = $corr % 45;
   }
   return $out;
}


1;

__END__

=head1 NAME

PDF::Reuse::Scramble - Scramble data transfer between Perl - Acrobat JavaScript

=head1 SYNOPSIS

my ($longKey, $shortKey, $random, $JavaScriptCode) = B<authorize>();

my $codedString = B<encrypt>('String to be scrambled', $shortKey, $random);

my $decodedString = B<decrypt>($codedString, $shortKey, $random);

=head1 ABSTRACT

This module has subroutines in Perl and corresponding functions in Acrobat
JavaScript to encrypt and decrypt data transferred between Perl and a PDF-
document and back to Perl. There is also a subroutine/function in both languages
to create the keys used for the scrambling.

=head1 DESCRIPTION

This is an experimental module. It should work for Acrobat Reader 5.0.5 or higher.

The authorize function creates a short key, a long key, a random string and a string
with JavaScript code. An internal match string is also created. The random string is
used in every process.

Data is encrypted with the B<short key>.

The scrambled data together with generated JavaScript code is put in the new
PDF-document.

When the user opens the document for the first time, he has to be authorized. Then 
the keys and the internal match string are recreated. If the new and an old match 
strings are equal, there is a good chance that the new keys also are correct, but
there is no guarantee ! (The match strings are only present to help the user avoid
small spelling mistakes. Big errors might not be detected.)

Data is decrypted with the B<short key>.

When data is sent back to the server, the B<long key> will be used both to encrypt
and decrypt it.

=head1 FUNCTIONS

=head2 authorize - Create keys for encryption/decryption and JavaScript code 

($longKey, $shortKey, $randomString, $JavaScriptCode = 
                              authorize([$userId, $passWord, $seed])

returns a long key, a short key, a random string and a string with JavaScript code
to be inserted in a PDF-document. It will be a JavaScript version of the functions
described in this document: 'authorize', 'encrypt' and 'decrypt'

The function will prompt for an userid and/or password, if they are not specified
as parameters. Each of them have to be at least 5 characters long.

Seed will be used for 'srand'. If it is not specified 'time' will be used.

=head2 encrypt - Scramble/encrypt a string 

$encoded = encrypt($stringToEncode, $key, $randomString)

returns an hex-encoded string which has been encrypted/scrambled

=head2 decrypt - Translate a scrambled string to normal text 

$text = decrypt($encodedString, $key, $randomString)

returns a decrypted string.

=head1 EXAMPLE

First we need a JavaScript file which defines interactive fields and buttons
and assigns values to them ('fab.js'):

   function fab()   
   {  var param = fab.arguments;       // Here are the parameters
      var page  = param[0];            // The first 3 parameters 
      var x     = param[1];            // are not encrypted
      var y     = param[2];
      var l;     
      var d;
      var labelText = [ "Mr_Ms", "First_Name", "Surname",
                        "Address", "City", "Zip_Code", "Country",
                        "Phone", "Mobile_Phone", "E-mail",
                        "Company", "Order_1", "Order_2",
                        "Order_3" ];   
      var k = 3;
      for ( var i = 0; i < labelText.length; i++)
      {   l = x + 80;               // length of the label
          d = y - 15;               // depth / hight

          //
          // a label field is created
          //

          var fieldName = labelText[i] + "Label";
          var lf1       = this.addField(fieldName, "text", page, [x,y,l,d]);
          lf1.fillColor = color.white;
          lf1.textColor = color.black;
          lf1.readonly  = true;
          lf1.textSize  = 12;
          lf1.defaultValue = labelText[i];
          lf1.value     = labelText[i];
          lf1.display   = display.visible;

          //
          // a text field for the customer to fill-in his/her data is created 
          //
  
          x = l + 2;
          l = x + 200;
          var tf1         = this.addField(labelText[i], "text", page, [x,y,l,d]);
          tf1.fillColor   = ["RGB", 1, 1, 0.94];
          tf1.strokeColor = ["RGB", 0.7, 0.7, 0.6];
          tf1.textColor   = color.black;
          tf1.borderStyle = border.s;
          tf1.textSize    = 12;
          tf1.display     = display.visible;

          //
          // Here below encrypted parameters are handled
          // 

          if (param[k])
          {   tf1.value        = decrypt(param[k]);
              tf1.defaultValue = tf1.value;
          }
          x = x - 82    // move 82 pixels to the left
          if (i == 3)
          {  y = y - 90;}
          else
          {  y = y - 17;   // move 17 pixels down
          }
          k++;
      }

      //
      // The update button is created
      //

      y = y + 34;
      x = x + 310;
      l = x + 75;
      d = y - 30;
      var f = this.addField("ButUpdate","button", page , [x,y,l,d]);
      f.setAction("MouseUp", "sendUpdates()");
      f.userName = "Press here to send updated data from this form";
      f.buttonSetCaption("Update");
      f.borderStyle = border.b;
      f.fillColor   = ["RGB", 0.3, 0.7, 0.3];
      
      //
      // The mail button
      //

      x = x + 100;
      l = x + 75;
      var m = this.addField("ButMail","button", page , [x,y,l,d]);
      m.setAction("MouseUp", "mailUpdates()");
      m.userName = "Press here to send data from this form by e-mail";
      m.buttonSetCaption("Mail");
      m.borderStyle = border.b;
      m.fillColor   = ["RGB", 1, 0.8, 0.4];          
   }

   function sendUpdates()
   {  //
      // To be sure that the keys are defined
      //

      authorize();

      //
      // If the authorizing failed, nothing will be sent
      //

      if (! fullKey)
         return;      
      var str = 'r=' + scramble + '&' + 're=' + encrypt(scramble) + '&';
      for (var i = 0; i < this.numFields; i++)
      {   var theName = this.getNthFieldName(i);
          var f = this.getField(theName);
          if ((f.type == 'text') && (f.defaultValue != f.value))

          // 
          // Field values are encrypted
          //
 
          {   str = str + theName + '=' + encrypt(f.value) + '&';}
      }
      var dest = 'http://127.0.0.1:80/cgi-bin/update.pl?cust=' 
                                  + getCust() + '&' + str; 
      this.getURL(dest, false);
   }
   function mailUpdates()
   {  authorize();
      if (! fullKey)
         return;
      var str = 'cust=' + getCust() + '&';
      for (var i = 0; i < this.numFields; i++)
      {   var theName = this.getNthFieldName(i);
          var f = this.getField(theName);
          if ((f.type == 'text') && (f.defaultValue != f.value)) 
          {   str = str + theName + '=' + encrypt(f.value) + '&';}
      }
      app.mailMsg( {bUI: true, cTo: "com@company.com", 
                    cSubject: "This is the subject", cMsg: str} );
   }

Here is a Perl program which creates a PDF-document

     use PDF::Reuse;
     
     #########################################################
     # You have to specify which subroutines to use, or :all
     #########################################################
     
     use PDF::Reuse::Scramble qw(:all);
     use strict;
     
     ##########################
     # Data about the customer
     ##########################

     my $customerNo   = 5;  
     my @customerData = ('Mr', 'Peter', 'Johansson', 'Kungsgatan 9', 'Olovstad',
                         'SE-10010', 'Sweden', '+46119-23456', '+4670-777777',
                         'pj@com', 'Tot. Invented Inc.');

     ####################################
     # The document should be compressed 
     # to keep its' size down
     ####################################

     prFile('hidden.pdf');
     prCompress(1);

     #############################################################
     # Keys are calculated and JavaScript code is "generated"
     #
     # As no userid or password are defined here, the subroutine
     # will ask for those values. (Don't use characters from an
     # extended character set. Your operating system and Acrobat/
     # Reader might handle them differently)
     #############################################################

     my ($fullKey, $halfKey, $random, $jsCode) = authorize();

     #######################################################################
     # The JavaScript functions "authorize", "crypt" and "decrypt" will be 
     # added. "authorize" will run when the document is opened
     #######################################################################

     prJs($jsCode);
     prInit("authorize();");

     ######################################################
     # Here the full decryption key is saved in a file
     # instead of a database, just for this demonstration
     ######################################################

     my $secrets = 'run.txt';
     open (OUTFILE, ">$secrets") || die $!;
     print OUTFILE "$fullKey\n";
     print OUTFILE $random;
     close OUTFILE;

     ############################################
     # A function which always will give a fixed
     # value for this PDF-document
     ############################################

     prJs("function getCust() { return '$customerNo'; }");

     ########################################################
     # Data for the fill-in form is prepared and "encrypted"
     ########################################################

     my $parameters = "0, 100, 800";
     for (@customerData)
     {  $parameters .= ",'" . encrypt($_, $halfKey, $random) . "'";
     }
     ##########################################################
     # The JavaScript functions for the fill-in form is added 
     # and initiated
     ##########################################################

     prJs('fab.js');
     my $jsCode = "fab($parameters)";
     prInit($jsCode);

     ##########################################################
     # To show that you also can transfer encrypted data with 
     # the help of prField, and how to get it decrypted (be 
     # careful with all double and single quotes)
     ##########################################################

     my $sentence = encrypt('Something really secret', $halfKey, $random);
     prField('Order_2', "js: decrypt('$sentence')");

     prEnd();

And here at last is a little cgi-program 'update.pl' which receives encrypted
data from the PDF-document, decrypts it, and sends the result back.

   use PDF::Reuse;
   use PDF::Reuse::Scramble qw(decrypt);
   use strict;

   my $x = 25;
   my $y = 790;
   my $step = 18;
   my ($string, %data, $value, $key);

   ###############################
   # First get data to work with 
   ###############################

   if ( $ENV{'REQUEST_METHOD'} eq "GET" 
   &&   $ENV{'QUERY_STRING'}   ne '') 
   {  $string = $ENV{'QUERY_STRING'};
   }

   ###############################################
   # Split and decode the hex-encoded strings
   # Create a hash with user data
   ###############################################
   for my $pair (split('&', $string)) 
   {  if ($pair =~ /(.*)=(.*)/)                     # found key=value;
      {   ($key,$value) = ($1,$2);                  # get key, value.
           $value =~ s/\+/ /g;
           $value =~ s/%(..)/pack('c',hex($1))/eg;  # Not really necessary here
           $data{$key} = $value;                    # Create the hash.
      }
   }

   #######################
   # Get the secret data
   #######################

   my $infile = 'run.txt';
   open (INFILE, "$infile");
   my $fullKey = <INFILE>;
   my $random  = <INFILE>;
   close INFILE;
   chomp($fullKey);

   #####################
   # Create new output
   #####################

   $| = 1;
   print STDOUT "Content-Type: application/pdf \n\n";

   prFile();
   prCompress(1);
   prTouchUp(0);
   prFontSize(16);

   #####################################################################
   # First a little check that the random string and the encrypted one
   # are equal. In a real situation, it is probably NOT a good idea
   # to put an encrypted and unencrypted value close to each other 
   #####################################################################

   if ((exists $data{'r'}) && (exists $data{'re'}))
   {  if ( $data{'r'} eq decrypt($data{'re'}, $fullKey, $random))
      {  prText($x, $y, "The messages are valid");
      }
      else
      {  prText($x, $y, "The messages are invalid");
      }
      $y -= $step * 3;
   }

   ###############################################
   # The transferred data is decrypted and shown
   ###############################################

   for $key (keys %data)
   {  if (($key eq 'cust') || ($key eq 'r'))
      {  prText($x, $y, "$key : $data{$key}");
      }
      else
      {  my $str = decrypt($data{$key}, $fullKey, $random);
         prText($x, $y, "$key : $str");
      }
      $y -= $step;
      if ($y < 40)
      {  prPage();
         $y = 790;
      }
   }
   prEnd();

=head1 SEE ALSO

PDF::Reuse

PDF::Reuse::Tutorial

=head1 AUTHOR

Lars Lundberg, Solidez HB, elkelund@worldonline.se

=head1 COPYRIGHT AND LICENSE

Copyright 2003 by Lars Lundberg

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself.

=head1 DISCLAIMER

As I have not worked earlier with cryptography, I am grateful for all suggestions
regarding this module.

You get this module free as it is, but nothing is guaranteed to work, whatever 
implicitly or explicitly stated in this document, and everything you do, 
you do at your own risk - I will not take responsibility 
for any damage, loss of money and/or health that may arise from the use of this document!
