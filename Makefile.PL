use 5.006;
use ExtUtils::MakeMaker;
WriteMakefile( 'NAME'         => 'PDF::Reuse::Scramble',
               'VERSION_FROM'	=> 'Scramble.pm', 
               'PREREQ_PM'    => { Exporter       => 0},
                  ($] >= 5.005 ?    
               (ABSTRACT_FROM => 'Scramble.pm',
       AUTHOR     => 'Lars Lundberg, Solidez HB elkelund@worldonline.se') : ()),
);
