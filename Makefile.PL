use 5.006;
use ExtUtils::MakeMaker;
WriteMakefile( 'NAME'         => 'PDF::Reuse::Scramble',
               'VERSION_FROM'	=> 'Scramble.pm', 
               'PREREQ_PM'    => { PDF::Reuse       => 0},
                  ($] >= 5.005 ?    
               (ABSTRACT => 'Scrambles/encrypts data to and from PDF documents',
       AUTHOR     => 'Lars Lundberg, Solidez HB elkelund@worldonline.se') : ()),
);
