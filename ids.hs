import System.Environment
import System.IO
import Data.List (elemIndex)
import qualified Data.Map as Map
import qualified Data.List.Split as Split -- splitOn
import qualified Data.Char as Char -- toUpper

-- USAGE 
-- ids.exe packetfile rulesfile configfile outputfile

data Rule = AlertRule { sid :: String
                      , message :: String
                      , protocol'AlertRule :: String
                      , srcIP'AlertRule :: String
                      , srcPorts :: [String]
                      , destIP'AlertRule :: String
                      , destPorts :: [String]
                      } deriving (Show)
data Alert = Alert { packetID :: String
                   , connection'Alert :: Connection
                   , rule :: Rule
                   , datetime'Alert :: String
                   , origin :: String
                   , description :: String
                   } deriving (Show)
data Packet = Packet { id'Packet :: String
                     , datetime'Packet :: String
                     , connection :: Connection
                     } deriving (Show)
data Connection = Connection { protocol'Connection :: String
                             , srcIP'Connection :: String
                             , srcPort :: Maybe String
                             , destIP'Connection :: String
                             , destPort :: Maybe String
                             } deriving (Show)

-- Hardcoded
testConfig = Map.fromList $ [("$HOME_NET","10.10.10.2")
                            ,("$EXTERNAL_NET", "10.10.10.11")
                            ,("$SMTP_SERVERS","10.10.10.2")
                            ,("$HTTP_SERVERS","10.10.10.2")
                            ,("$SQL_SERVERS","10.10.10.2")
                            ,("$TELNET_SERVERS","10.10.10.2")
                            ,("$HTTP_PORTS","[80,81]")]
getHardcodedOrigin sid = 
    deMaybe "Unknown" id $ Map.lookup sid $ Map.fromList [("105","External")
                                                 ,("254","External")
                                                 ,("463","External")
                                                 ,("669","External")
                                                 ,("693","External")
                                                 ,("709","External")
                                                 ,("813","External")
                                                 ,("1685","External")
                                                 ,("1776","External")
                                                 ,("26924","Internal")]
getHardcodedDescription sid = 
    deMaybe "Unknown" id $ Map.lookup sid $ Map.fromList [("105","This client program of a backdoor malware executes commands on a remote computer infected with the server program. This program enables a remote hacker to have full access to the files on the system where the backdoor server program is installed.")
                                                 ,("254","This is presumably from an attacker engaged in a race condition to respond to a legitimate DNS query. An attacker may sniff a DNS query requeting an address record and attempt to respond before an actual DNS server can. The spoofed response is atypical because it does not include the authoritative DNS servers in the returned record. A legitimate DNS response will likely return the names of the authoritative DNS servers. The response associated with this traffic has a DNS time-to-live value of one minute. It is suspected that the TTL is set to expire quickly to eliminate any evidence of the spoofed response.")
                                                 ,("463","ICMP Type 7 is not defined for use and is not expected network activity. Any ICMP datagram with an undefined ICMP Code should be investigated.")
                                                 ,("669","Sendmail 8.6.10 and earlier versions contain a vulnerability related to the parsing of linefeed characters in commands passed from ident to Sendmail. An attacker can use a specially crafted command with linefeeds in an ident response to Sendmail. The message is not properly parsed and Sendmail forwards the response, with included commands, to its queue. The commands are then executed while the message awaits delivery in the Sendmail queue, causing the included arbitrary code to be executed on the server in the security context of Sendmail.")
                                                 ,("693","This event is generated when an attacker issues a special command to an SQL database that may result in a serious compromise of all data stored on that system.\n\nSuch commands may be used to gain access to a system with the privileges of an administrator, delete data, add data, add users, delete users, return sensitive information or gain intelligence on the server software for further system compromise.\n\nThis connection can either be a legitimate telnet connection or the result of spawning a remote shell as a consequence of a successful network exploit.")
                                                 ,("709","This event is generated when an attempt is made to login to a server using the username 4Dgifts via Telnet. This is a default account on some SGI based machines. The password may also be 4Dgifts or it may not have a password assigned.\n\nRepeated events from this rule may indicate a determined effort to guess the password for this account.")
                                                 ,("813","Directory traversal attacks usually target web, web applications and ftp servers that do not correctly check the path to a file when requested by the client.\n\nThis can lead to the disclosure of sensitive system information which may be used by an attacker to further compromise the system.")
                                                 ,("1685","This event is generated when an attacker issues a special command to an Oracle database that may result in a serious compromise of all data stored on that system.\n\nSuch commands may be used to gain access to a system with the privileges of an administrator, delete data, add data, add users, delete users, return sensitive information or gain intelligence on the server software for further system compromise.\n\nThis connection can either be a legitimate telnet connection or the result of spawning a remote shell as a consequence of a successful network exploit.\n\nOracle servers running on a Windows platform may listen on any arbitrary port. Change the $ORACLE_PORTS variable in snort.conf to \"any\" if this is applicable to the protected network.")
                                                 ,("1776","This event is generated when the MySQL command 'show' is used to garner a list of MySQL databases being served by the MySQL daemon.\n\nThis connection can either be a legitimate telnet connection or the result of spawning a remote shell as a consequence of a successful network exploit.")
                                                 ,("26924","No documentation available.")]

showPretty :: Alert -> String
showPretty alert =
    let (Alert packetID (Connection protocol srcIP srcPort destIP destPort) (AlertRule sid message _ _ _ _ _) datetime origin description) = alert
        portFunc = deMaybe "None" id
    in "Alert: \"" ++ message ++ "\" [" ++ sid ++ "] in packet id: " ++ packetID ++ "\nDetected: " ++ datetime ++ "\nProtocol: " ++ protocol ++ "\nSource IP: " ++ srcIP ++ "\nSource port: " ++ (portFunc srcPort) ++ "\nDestination IP: " ++ destIP ++ "\nDestination port: " ++ (portFunc destPort) ++ "\nOrigin: " ++ origin ++ "\nDescription: " ++ description ++ "\n\n"

deMaybe :: y -> (x -> y) -> Maybe x -> y
deMaybe ifNothing _ Nothing = ifNothing
deMaybe _ ifSomething (Just something) = ifSomething something

descriptions :: [Alert] -> String
descriptions alerts =
    foldr (++) "" . map showPretty $ alerts

main = do
  args <- getArgs
  case args of
    [pcapFilename,rulesFilename,configFilename,outFilename] -> 
        do
          pcapContents <- readFile pcapFilename
          rulesContents <- readFile rulesFilename
          configContents <- readFile configFilename
          writeFile outFilename (doSnort rulesContents pcapContents configContents)
    [pcapFilename,rulesFilename,configFilename] -> 
        do
          pcapContents <- readFile pcapFilename
          rulesContents <- readFile rulesFilename
          configContents <- readFile configFilename
          putStrLn (doSnort rulesContents pcapContents configContents)
    _ -> putStrLn "Usage: ids.exe PCAP_FILE RULES_FILE CONF_FILE [OUT_FILE]\n\nNote that PCAP_FILE must be human a readable output file from snort."

doSnort rulesContents pcapContents configContents =
  let configMap = (parseConfig configContents)
      rules = (parseRules rulesContents configMap)
      packets = (parsePcap pcapContents)
  in descriptions (maliciousPackets rules packets)

debugConcat contents1 contents2 contents3 =
    concat $ map (take 20) [contents1,contents2,contents3]

-- testConfig is hardcoded and was used for testing here
parseConfig configContents = 
     let tokenizedNoComments = filter ((/='#') . (!!0) . (!!0)) . map tokenizeBash . filter (/="") . lines $ configContents
         foldHelper = (\ mapping tokenizedLine ->
                           let var = '$': (tokenizedLine !! 1)
                               val = replaceMany mapping $ tokenizedLine !! 2
                           in Map.insert var val mapping)
     in foldl foldHelper Map.empty tokenizedNoComments
    
parseRules :: String -> Map.Map String String -> [Rule]
parseRules rulesContents configMap =
    map (parseRule configMap) (filter (/="") (lines rulesContents))

parseRule :: Map.Map String String -> String -> Rule
parseRule configMap ruleLine =
    AlertRule sid message protocol srcIP (splitPorts srcPorts) destIP (splitPorts destPorts)
    where ["alert", protocol, srcIP, srcPorts, "->", destIP, destPorts] = map (replaceMany configMap) . tokenizeBash . takeWhile (/='(') $ ruleLine
          extraSettings = parseExtra $ dropWhile (/='(') ruleLine
          sid = deMaybe "None" id (Map.lookup "sid" extraSettings)
          message = deMaybe "None" id (Map.lookup "msg" extraSettings)
                                                                                
splitPorts ('[':ports) =
    let noBrackets = takeWhile (/=']') ports
    in wordsWith ',' noBrackets
splitPorts port = [port]

wordsWith :: Char -> String -> [String]
wordsWith delim str =
    case splitOn delim str of
      (left,Nothing) -> [left]
      (left,Just right) -> left : (wordsWith delim right)

-- Backup implementation
--wordsWith :: Char -> String -> [String]
--wordsWith delim str =
--    Split.splitOn [delim] str


replaceMany :: Map.Map String String -> String -> String
replaceMany wordMap str =
    foldl helper str (Map.toList wordMap)
    where helper = (\ str (var,val) -> replaceAll var val str)

replaceAll :: String -> String -> String -> String
replaceAll var val "" = ""
replaceAll var val str@(s:ss)
    | startsWith var str = val ++ (drop varLen str)
    | otherwise = s : (replaceAll var val ss)
    where varLen = length var
    
startsWith [] haystack = True
startsWith needle@(n:ns) haystack@(h:hs)
    | n == h = startsWith ns hs
    | otherwise = False

parsePcap :: String -> [Packet]
parsePcap pcapContents = 
    map parsePacket . filter (/="") $ Split.splitOn "=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n\n" pcapContents

parsePacket :: String -> Packet
parsePacket packetStr = 
    let (line1:line2:ls) = map tokenizeBash $ lines packetStr
        extraStuff = parseExtraHelper $ drop 1 line2
        Just packetID = Map.lookup "ID" extraStuff
        datetime = line1 !! 0
        protocol = line2 !! 0
        (srcIP,srcPort) = splitOn ':' $ line1 !! 1
        (destIP,destPort) = splitOn ':' $ line1 !! 3
    in Packet packetID datetime (Connection protocol srcIP srcPort destIP destPort)

maliciousPackets :: [Rule] -> [Packet] -> [Alert]
maliciousPackets rules packets =
    filterNothings $ map (maliciousPacketAlert rules) packets

-- Shows the first applicable alert
maliciousPacketAlert :: [Rule] -> Packet -> Maybe Alert
maliciousPacketAlert rules packet = 
    case dropWhile (not . isMaliciousPacket packet) $ rules of
      (rule:_) -> Just $ constructAlert rule packet
      otherwise -> Nothing

constructAlert :: Rule -> Packet -> Alert
constructAlert rule packet =
    Alert packetID connection rule datetime origin description
    where Packet packetID datetime connection = packet
          origin = getHardcodedOrigin (sid rule) --hardcoded
          description = getHardcodedDescription (sid rule) --hardcoded

isMaliciousPacket :: Packet -> Rule -> Bool
isMaliciousPacket packet rule =
    (map Char.toUpper p'protocol) == (map Char.toUpper r'protocol)
    && p'srcIP == r'srcIP
    && (p'srcPort `elem` map Just r'srcPorts || "any" `elem` r'srcPorts)
    && p'destIP == r'destIP
    && (p'destPort `elem` map Just r'destPorts || "any" `elem` r'destPorts)
    where AlertRule _ _ r'protocol r'srcIP r'srcPorts r'destIP r'destPorts = rule
          Packet packetID datetime (Connection p'protocol p'srcIP p'srcPort p'destIP p'destPort) = packet
    
filterNothings :: [Maybe a] -> [a]
filterNothings =
    map (\ (Just x) -> x) . filter isSomething

isSomething :: Maybe a -> Bool
isSomething Nothing = False
isSomething (Just x) = True

tokenizeBash :: String -> [String]
tokenizeBash str = tokenizeBashHelper [] str

--acc is current word
tokenizeBashHelper :: String -> String -> [String]
tokenizeBashHelper [] [] = []
tokenizeBashHelper acc [] = [acc]
tokenizeBashHelper [] (x:xs)
    | x == '"' = tokenizeBashHelperQuoted [] xs
    | x == ' ' = (tokenizeBashHelper [] xs)
    | x == ';' || x == '\n' = [[x]] ++ (tokenizeBashHelper [] xs)
    | otherwise = tokenizeBashHelper [x] xs
tokenizeBashHelper acc (x:xs)
    | x == '"' = tokenizeBashHelperQuoted acc xs
    | x == ' ' = [acc] ++ (tokenizeBashHelper [] xs)
    | x == ';' || x == '\n' = [acc] ++ [[x]] ++ (tokenizeBashHelper [] xs)
    | otherwise = tokenizeBashHelper (acc ++ [x]) xs

--does not split words until '"' is found
--acc is current word
tokenizeBashHelperQuoted :: String -> String -> [String]
tokenizeBashHelperQuoted [] [] = []
tokenizeBashHelperQuoted acc [] = [acc]
tokenizeBashHelperQuoted [] (x:xs)
    | x == '"' = tokenizeBashHelper [] xs
    | otherwise = tokenizeBashHelperQuoted [x] xs
tokenizeBashHelperQuoted acc (x:xs)
    | x == '"' = tokenizeBashHelper acc xs
    | otherwise = tokenizeBashHelperQuoted (acc ++ [x]) xs

splitOn :: Char -> String -> (String, Maybe String)
splitOn delim str =
    case elemIndex delim str of 
      Nothing -> (str, Nothing)
      Just index -> let (left,(_:right)) = splitAt index str
                    in (left, Just right)

parseExtra :: String -> Map.Map String String
parseExtra extra =
    parseExtraHelper . tokenizeBash . dropWhile (=='(') $ extra

parseExtraHelper =
    Map.fromList . map (removeNothing . (splitOn ':')) . filter (/=";")
    where removeNothing = (\ (a,thing) -> (a,(deMaybe "" id thing)) )
