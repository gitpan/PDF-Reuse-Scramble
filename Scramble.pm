package PDF::Reuse::Scramble;

use 5.006;
use strict;
use warnings;
use integer;

require PDF::Reuse;

our $VERSION = '0.04';

sub new
{  my $class = shift;
   my $self  = {};
   bless $self, $class;
   my %param = @_;
   for (keys %param)
   {   my $key = lc($_);
       $self->{$key} = $param{$_}; 
   }
   my $user    = $self->{'user'}     || ' ';
   my $pass    = $self->{'password'} || ' ';
   my $seed    = $self->{'seed'}     || time;
   my $nouser  = $self->{'nouser'};
   my $nopass  = $self->{'nopassword'};
   my $title   = $self->{'title'} || 'Password';
   my $trans   = $self->{'transaction'};
   my $warning = $self->{'warning'} || 
               'Authorization failed, encrypted data will not be shown';
  
   srand($seed);
   if (! defined $trans)
   {   $trans  = uc(sprintf("%x",rand(999999)));
       $trans .= sprintf("%x",rand(999999));
       $trans .= uc(sprintf("%x",rand(999999)));
       $trans .= sprintf("%x",rand(999999));
       $trans .= uc(sprintf("%x",rand(999999)));
   }
   if (length($trans) < 5)
   {   die "Transaction code has to be at least 5 characters long, aborts\n"; 
   }
   if  (($nouser) && ($user eq ' '))
   {   $user = uc(sprintf("%x",rand(999999)));
       while (length($user) < 5)
       {   $user .= uc(sprintf("%x",rand(999999)));
       }
   } 
   if (($nopass) && ($pass eq ' '))
   {   $pass = sprintf("%x",rand(999999));
       while (length($pass) < 5)
       {   $pass .= sprintf("%x",rand(999999));
       }
   } 
   while ((length($user) < 5) || (length($pass) < 5))
   {   if (length($user) < 5)
       {  print "User     (at least 5 letters) : ";
          $user = <STDIN>;
          chomp($user);
       }
       if (length($pass) < 5)
       {  print "Password (at least 5 letters) : ";
          $pass = <STDIN>;
          chomp($pass);
       }
   } 
   my $rest = 0;
   my $fullKey = '';
   my $matchKey = '';
   my $num2 = 17;
   my $rest2 = 0;
   my $corr = ord(substr($pass, 0, 1)) + ord(substr($user, 0, 1));
   my $lr = length($trans) - 1;
   my $k = $corr % $lr;
   my $lu = length($user) - 1;
   my $j = $corr % $lu;
   $corr = ($corr + ord(substr($trans, $k, 1)) + $j + $k) % 37;
   for (my $i = 0; $i < length($pass); $i++)
   {  my $num1 = ord(substr($pass,$i,1)) + $corr;
      my $spar = $num1 % 53;
      $num1 += ($i < length($user)) ? ord(substr($user, $i, 1)) : $i ;
      my $num3 = ord(substr($trans, $k, 1)) % 53;
      $num1 += ($spar > $num3 ) ? $num3 : ord(substr($trans, $k, 1));
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
      $corr = ord(substr($pass, $i, 1)) + ord(substr($user, $j, 1))
               + ord(substr($trans, $k, 1)) + $i + $j + $k;
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
  my $jsUser = ($nouser) ? $user : ' ';
  my $jsPass = ($nopass) ? $pass : ' ';
  my $str = <<"EOF";
function authorize()
{ var chances = 0;
  var User = '$jsUser';
  var Pass = '$jsPass';
  scramble = '$trans';
  while (chances < 3)
  { if (User.length < 4)
       User = app.response('',"Userid",'', true);
    if (Pass.length < 4)
       Pass = app.response('','$title','', true);
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
     chances = 7;
   else
   {  halfKey = '';
      fullKey = '';
   }     
   chances++;
   Pass = '$jsPass';
   User = '$jsUser';
  }
  if (chances < 7)
     app.alert('$warning');       
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
  $self->{fullKey} = $fullKey;
  $self->{halfKey} = $halfKey;
  $self->{transaction} = $trans;
  $self->{jsCode} = \$str; 
  return $self;
}

##############################################################
# To scramble and translate a string to a hex-encoded string 
##############################################################
sub encrypt
{  my $self = shift;
   my $word = shift;
   my $key  = shift || $self->{halfKey};
   my $scramble = $self->{transaction};
   return unless ($word);
 
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
{  my $self = shift;
   my $word = shift;
   my $key  = $self->{key} || $self->{fullKey};
   my $scramble = $self->{transaction};
   my $out = '';
   return unless ($word);
   if ($word =~ m/^(%[0-9A-F]{2})+\&?$/gso)
   {  $word =~ s/%(..)/pack('C',hex($1))/eg;
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

sub getJsCode
{  my $self = shift;
   return ${$self->{jsCode}};
}
sub getHalfKey
{  my $self = shift;
   return $self->{halfKey};
}
sub getFullKey
{  my $self = shift;
   return $self->{fullKey};
}
sub getTransaction
{  my $self = shift;
   return $self->{transaction};
}
sub getKeys
{  my $self = shift;
   return ($self->{fullKey}, $self->{halfKey}, $self->{transaction});
}
sub initJsCode
{  my $self = shift;
   PDF::Reuse::prJs($self->getJsCode());
   PDF::Reuse::prInit("authorize();");
}

sub exportJsCode
{  my $self = shift;
   PDF::Reuse::prJs($self->getJsCode());
}


sub fieldValue
{  my $self = shift;
   my $field = shift;
   my $value = shift;
   $value = $self->encrypt($value);
   PDF::Reuse::prField($field, "js: decrypt('$value')");
}

sub decryptInit
{  my $class = shift;
   my $self  = {};
   bless $self, $class;
   my %param = @_;
   for (keys %param)
   {   my $key = lc($_);
       $self->{$key} = $param{$_}; 
   }
   return $self;
}

1;

__END__

=head1 NAME

PDF::Reuse::Scramble - Scramble data transfer between Perl - Acrobat JavaScript

=head1 SYNOPSIS

A little test where everything is done in Perl. In a real case, JavaScript
would be involved.

   use PDF::Reuse::Scramble;
   use strict;

   #############################################################
   # As there are no userid or password as parameters to new(),
   # the system will ask for those two strings. (Don't use 
   # characters from an extended character set. Your operating
   # system and Acrobat/Reader might have different opinion
   # about character and numeric order)
   #############################################################
 
   my $s = PDF::Reuse::Scramble->new();

   my ($longKey, $shortKey, $transaction) = $s->getKeys();

   my $codedString = $s->encrypt('This text will be used');
   print "$codedString\n";

   ####################################################################
   # encrypt uses the short key by default, so that one has to be used
   # here for decryption. (If it had been encrypted by JavaScript, on
   # the other hand, the long key would have been used)
   ####################################################################
   
   my $d = PDF::Reuse::Scramble->decryptInit(key         => $shortKey,
                                             transaction => $transaction);
   my $text = $d->decrypt($codedString);
   print "$text\n";


=head1 ABSTRACT

This module has subroutines in Perl and functions in Acrobat JavaScript to encrypt
and decrypt data transferred between Perl and a PDF-document and back to Perl. There
is also a subroutine/function in both languages to create the keys used for 
the scrambling.

=head1 DESCRIPTION

A:

If your users have Acrobat Reader 4.0 and higher, you can use this module to verify
who updated an interactive PDF-form. It creates an off-line login/authorization
routine in JavaScript and it has encryption/decryption functions.

The user fills-in the form and just before he sends data to your server, he has to
identify himself with a userid and password. If it seemed like he has identified 
himself correctly, his data is encrypted and sent.
Your server needs a long key produced from his userid, password and a transaction 
code to be able read the messages correctly.

B:

If your users have Acrobat Reader 5.0.5 or higher it also makes it possible to use
the Reader and Acrobat in a restricted way so you can decide who can read the 
data of the form. Also answers can be sent by mail.

The process then looks a little like this:

Data to be inserted in a PDF-document is encrypted with a B<short key> and
a transaction code.

When the user opens the document for the first time, he has to be authorized. 
He will be prompted for his userid and password, if this dialog hasn't been
suppressed. Encryption keys and an internal match string are recreated.
If the new and old match strings are equal, there is a good chance that the new
keys also are correct, but there is no guarantee ! (The match strings are only
present to help the user avoid small spelling mistakes. Big errors might not be
detected.)

When data is sent back to the server, a B<long key> together with a transaction
code will be used both to encrypt and decrypt it.

=head1 Encryption methods

=head2 new

    new( user        => $user,
         password    => $passWord,
         seed        => $seed,
         noUser      => $nouser,
         noPassword  => $nopassword,
         title       => $title,
         transaction => $trans,
         warning     => $message);
   
Creates a new instance of an encryption object.

All the parameters are optional.
If 'noUser' is set to something, Acrobat/Reader will not prompt for an userid when
the generated PDF-document is opened, and the system will generate an internal userid,
if it has not been given as the 'user' parameter. The same goes for 'noPassword'. 
The user will not be prompted for it, and an internal one will be generated if it is
not given by the 'password' parameter.

Both userid and password have to be at least 5 characters long.

Seed will be used for 'srand'. If it is not specified, 'time' will be used.

Title is the title of the password dialog in the PDF-document.

Transaction is a key component in the scrambling. By default it is random string,
around 20 bytes long, more or less unique for each document. It can be any string,
perhaps the same string for all users and every context, but then the encrypted data
is not connected to a special document. It has to be at least 5 characters long. 

Warning is the message you get if login/authorization has failed. If you don't
define anything it will be:
'Authorization failed, encrypted data will not be shown'.

=head2 decrypt 

    $text = $s->decrypt($encodedString)

returns a decrypted string.
It uses the long key to decrypt.
 

=head2 encrypt 

    $encoded = $s->encrypt($stringToEncrypt [,$key])

returns an hex-encoded string which has been encrypted/scrambled

$key is optional. Don't use this parameter when you send encrypted data to 
a PDF-document. The JavaScripts use only the short key to decrypt and the long
key to encrypt.

=head2 exportJsCode

Saves the generated JavaScript functions 'authorize', 'encrypt' and 'decrypt'
in the PDF-document you are creating. Nothing is initiated to run when the
document is opened the first time.

=head2 fieldValue

    $s->fieldValue($fieldName, $stringToEncrypt);

Encrypts a string. Makes the JavaScript function decrypt to be called when the
PDF-document is opened, and makes the decrypted value to be assigned to the field
with the name $fieldName.

N.B. Your user needs Acrobat/Reader 5.0.5 or higher.

=head2 getKeys

    ($fullKey, $halfKey, $transaction) = $s->getKeys();

Returns the keys used in the scrambling 

=head2 initJsCode

    $s->initJsCode();

Inserts a string with JavaScript code in the PDF-document you are creating.
It will be the JavaScript functions 'authorize', 'encrypt' and 'decrypt'.
'authorize' will be initiated to run when the document is opened the first time.

N.B. Your user needs Acrobat/Reader 5.0.5 or higher.

=head1 Decryption methods

=head2 initDecrypt

    $d->initDecrypt(key         => $key,
                    transaction => $transactionCode);

Creates a new decryption object.

=head2 decrypt 

    $text = $d->decrypt($encodedString)

returns a decrypted string.
Uses what has been defined as 'key' to decrypt.

=head1 Example

This should work for Acrobat/Reader 4.0 and higher. (So it should probably
work for most users.)

You have a fill-in form and now you are going to send it to a customer by mail.
You want to be sure that the one, who sends the answer back to you, really is your
customer and nobody else.

The name of the fill-in form is 'old.pdf'. It has a number of interactive fields and
a button which calls sendUpdates(); when you click on it.

This JavaScript is defined at document level:

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
      else
      {  var str = "Will try to send data." + "\r You will get a response. If not\r"
                 + "- you have to activate your internet connection and retry !";
         app.alert(str);
      }
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

Here is the program that generates the PDF-document

   use PDF::Reuse;
   use PDF::Reuse::Scramble;
   use strict;

   my $transaction = 'Registration';              # Case sensitive !

   ##########################################
   # Data about the customer from a database
   ##########################################

   my $userId   = 'Adam Andersson';               # Case sensitive !
   my $password = 'The 4th of July 1996';         # Case sensitive !
   my $custNo   = 20456; 

   prFile('verify.pdf');
   prCompress(1);
   my $s = PDF::Reuse::Scramble->new( user        => $userId,
                                      password    => $password,
                                      transaction => $transaction);

   #######################################################
   # The adjusted JavaScript functions authorize, encrypt
   # and decrypt are saved in the generated PDF-document
   #######################################################
   
   $s->exportJsCode();

   ########################################################
   # A little JavaScript for customer number is also saved
   ########################################################

   prJs("function getCust() { return '$custNo'; }");
 
   prDoc('old.pdf');
   prEnd();

When the user presses the button, he has to identify himself with a userid and
password, and the data, partly encrypted and hex encoded is sent.

At the server side some data is needed to decrypt the answer, among other things:

   # ...

   ############################################################
   # Customer number and transaction from the received message
   ############################################################

   my $custNo   = 20456;
   my $transaction = 'Registration';

   ##########################################
   # Data about the customer from a database
   ##########################################

   my $userId   = 'Adam Andersson';
   my $password = 'The 4th of July 1996'; 

   ################################################################ 
   # a 'Scramble' object is created. In it, the keys are recreated
   ################################################################

   my $s = PDF::Reuse::Scramble->new(user        => $userId,
                                     password    => $password,
                                     transaction => $transaction);

   # ...
 
   #######################################################################
   # Each encrypted and hex encoded string can now be decrypted like this 
   #######################################################################

   my $text = $s->decrypt($encodedString);

   ##########################################################################
   # if the value of 'valueIf' = 'It is valid', the right customer answered,
   # and the values of the other fields should also be reliable
   ##########################################################################


=head1 Examples for Acrobat 5.0/Reader 5.0.5 or higher

Sooner or later most users have upgraded to at least Acrobat/Reader 5.0.5 and
then these examples can be used.

=head2 A short example

You have a PDF-document with the interactive fields: field_1, field_2 and field_3 
(spelled exactly like that), which you want to fill with encrypted text. 
If your user writes the control code "AX225", he/she will be able to read the 
encrypted texts.

     use PDF::Reuse;
     use PDF::Reuse::Scramble;
     use strict;
     
     prFile('hidden1.pdf');
     prCompress(1);
     my $s = PDF::Reuse::Scramble->new( nouser => 1,
                                        password => 'AX225',
                                        title    => 'Control Code');
     $s->initJsCode();
     $s->fieldValue('field_1', 'This is the first secret');
     $s->fieldValue('field_2', 'This is the second secret');
     $s->fieldValue('field_3', 'This is the third secret');
     prDoc('old.pdf');
     prEnd();

=head2 A long example (more or less complete)

This example looks a little bit big, because it shows how different programs
interact. It is two Perl programs and also JavaScript embedded in a generated
PDF-document. And I have also tried to make it a 'complete example'. Cut and
paste, save it as files and try it. If you have a local web server, you could
run the programs at the directory where your server looks for CGI-programs.

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
      f.userName = "To send updated data (and get a response)";
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
      m.userName = "Send data from this form by e-mail";
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
      else
      {  var str = "Will try to send data." + "\r You will get a response. If not\r"
                 + "- you have to activate your internet connection and retry !";
         app.alert(str);
      }
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

Here is a Perl program which creates a PDF-document and uses 'fab.js'

     use PDF::Reuse;
     use PDF::Reuse::Scramble;
     use strict;
     
     #####################################################
     # Data about the customer, should be from a database
     #####################################################

     my $customerNo   = 5;  
     my @customerData = ('Mr', 'Peter', 'Johansson', 'Kungsgatan 9', 'Olovstad',
                         'SE-10010', 'Sweden', '+46119-23456', '+4670-777777',
                         'pj@com', 'Tot. Invented Inc.');

     my $userId       = '12Peter';                 # Case sensitive !
     my $password     = 'Crazy Horse';             # Case sensitive !

     #############################################################
     # The document should be compressed so the keys and para- 
     # meters are not directly visible (but it is not a big deal  
     # if they are seen), and it will have a more acceptable size
     #############################################################

     prFile('hidden.pdf');
     prCompress(1);

     #########################################################
     # Keys are calculated and JavaScript code is "generated"
     #########################################################

     my $s = PDF::Reuse::Scramble->new(user     => $userId,
                                       password => $password);

     ######################################################################
     # The JavaScript functions "authorize", "crypt" and "decrypt" will be 
     # inserted. "authorize" will run when the document is opened
     ######################################################################

     $s->initJsCode();

     ###############################################################
     # Here the full decryption key and transaction code are saved 
     # in a file instead of a database, just for this demonstration
     ###############################################################

     my $secrets = 'run.txt';
     my ($fullKey, $halfKey, $transaction) = $s->getKeys();
     open (OUTFILE, ">$secrets") || die $!;
     print OUTFILE "$fullKey\n";
     print OUTFILE "$transaction";
     close OUTFILE;

     ############################################
     # A function which always will give a fixed
     # value for this PDF-document
     ############################################

     prJs("function getCust() { return '$customerNo'; }");

     ########################################################
     # Data for the fill-in form is assigned and "encrypted"
     ########################################################

     my $parameters = "0, 100, 800";
     for (@customerData)
     {  $parameters .= ",'" . $s->encrypt($_) . "'";
     }
     ##########################################################
     # The JavaScript functions for the fill-in form is added 
     # and initiated
     ##########################################################

     prJs('fab.js');
     my $jsCode = "fab($parameters)";
     prInit($jsCode);

     ###########################################
     # An interactive field in the PDF-document  
     # will get an encrypted value 
     ###########################################

     $s->fieldValue('Order_2','Something really secret');

     prEnd();

And here at last is a little cgi-program 'update.pl' which receives encrypted
data from the PDF-document, decrypts it, and sends the result back.

   use PDF::Reuse;
   use PDF::Reuse::Scramble;
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

   ###########################################
   # Split and decode the hex-encoded strings
   # Create a hash with user data
   ###########################################
   for my $pair (split('&', $string)) 
   {  if ($pair =~ /(.*)=(.*)/)                     # found key=value;
      {   ($key,$value) = ($1,$2);                  # get key, value.
           $value =~ s/\+/ /g;
           $value =~ s/%(..)/pack('C',hex($1))/eg;  # Not really necessary here
           $data{$key} = $value;                    # Create the hash.
      }
   }

   #######################
   # Get the secret data
   #######################

   my $infile = 'run.txt';
   open (INFILE, "$infile");
   my $fullKey = <INFILE>;
   my $transaction  = <INFILE>;
   close INFILE;
   chomp($fullKey);

   #############################
   # Create a decryption object
   #############################

   my $d = PDF::Reuse::Scramble->decryptInit(key         => $fullKey,
                                             transaction => $transaction);

   ####################
   # Create new output
   ####################

   $| = 1;
   print STDOUT "Content-Type: application/pdf \n\n";

   prFile();
   prCompress(1);
   prTouchUp(0);
   prFontSize(16);

   ###################################################################
   # First a little check that the unencrypted transaction code, and 
   # the decrypted one are equal. In a real situation, it is probably  
   # not a good idea to put two such values close to each other 
   ###################################################################

   if ((exists $data{'r'}) && (exists $data{'re'}))
   {  if ( $data{'r'} eq $d->decrypt($data{'re'}))
      {  prText($x, $y, "The messages are valid");
      }
      else
      {  prText($x, $y, "The messages are invalid");
      }
      $y -= $step * 3;
   }

   ##############################################
   # The transferred data is decrypted and shown
   ##############################################

   for $key (keys %data)
   {  if (($key eq 'cust') || ($key eq 'r'))
      {  prText($x, $y, "$key : $data{$key}");
      }
      else
      {  my $str = $d->decrypt($data{$key});
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

I haven't worked very much with cryptography, so I am grateful for all suggestions
regarding this module.

You get this module free as it is, but nothing is guaranteed to work, whatever 
implicitly or explicitly stated in this document, and everything you do, 
you do at your own risk - I will not take responsibility 
for any damage, loss of money and/or health that may arise from the use of this document!
