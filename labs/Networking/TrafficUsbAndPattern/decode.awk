function hex(s,  i,n,c){n=0;for(i=1;i<=length(s);i++){c=index("0123456789abcdef",tolower(substr(s,i,1)))-1;n=n*16+c}return n}
BEGIN{
  L="abcdefghijklmnopqrstuvwxyz"; N="1234567890"; NS="!@#$%^&*()"
  split(" |-|=|[|]|\\|;|'|`|,|.|/", P, "|")
  split(" |_|+|{|}|\||:|\"|~|<|>|?", S, "|")
  U[44]=1;U[45]=2;U[46]=3;U[47]=4;U[48]=5;U[49]=6;U[51]=7;U[52]=8;U[53]=9;U[54]=10;U[55]=11;U[56]=12
}
/^#/ {next}
{
  h=$0; gsub(/[^0-9a-fA-F]/,"",h); if(length(h)!=16) next
  m=hex(substr(h,1,2)); k=hex(substr(h,5,2)); sh=(int(m/2)%2==1)||(int(m/32)%2==1)
  if(k==0) next
  if(k>=4&&k<=29){c=substr(L,k-3,1); if(sh)c=toupper(c); out=out c}
  else if(k>=30&&k<=39){out=out (sh?substr(NS,k-29,1):substr(N,k-29,1))}
  else if(k==40) out=out "\n"
  else if(k==43) out=out "\t"
  else if(k==42) out=substr(out,1,length(out)-1)
  else if(k in U) out=out (sh?S[U[k]]:P[U[k]])
  else out=out sprintf("<0x%02x>",k)
}
END{print out}
