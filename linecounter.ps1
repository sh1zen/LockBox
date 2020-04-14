$files = 0;
dir . -include *.c,*.cpp,*.h,*.hpp -Recurse | % {

$files++;

}

$i=0;
$k=0;
$words=0;

dir . -include *.c,*.cpp,*.h,*.hpp -Recurse | % {

$count = (gc $_).count; 

    if ($count) {
        if($_.Extension -eq ".cpp"){$cpp = $cpp + [int]$count;}
        elseif($_.Extension -eq ".c"){$c = $c + [int]$count;}
        elseif($_.Extension -eq ".hpp"){$hpp = $hpp + [int]$count;}
        elseif($_.Extension -eq ".h"){$h = $h + [int]$count;}
    } 

    $k =  $i/$files*100;
    $k = "{0:N0}" -f $k;

    $words = ((gc $_) | Measure-Object -word).Words + $words ;

    Write-Progress -Activity "Counting lines number:" -status "File $i completed $k%" -percentComplete ($k)
    $i++;
}

 write-host "`nTotal:";
 write-host "______________________________";
 write-host "`n  Files:  $files";
 write-host "  --------------------------";
 write-host "`n  .cpp  :  $cpp";
 write-host "`n  .c    :  $c";
 write-host "`n  .hpp  :  $hpp";
 write-host "`n  .h    :  $h";
 write-host "______________________________";

 $tot = $cpp+ $c + $hpp + $h;
 write-host "`n`nTotal lines: $tot";
  write-host "`nTotal words: $words`n`n";

pause