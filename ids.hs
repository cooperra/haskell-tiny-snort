import System.Environment
import System.IO
import Data.List (elemIndex)
import qualified Data.Map as Map
import qualified Data.List.Split as Split -- splitOn
import qualified Data.Char as Char -- toUpper

-- USAGE 
-- ids.exe packetfile rulesfile configfile outputfile

data Rule = AlertRule { protocol'AlertRule :: String
                      , srcIP'AlertRule :: String
                      , srcPorts :: [String]
                      , destIP'AlertRule :: String
                      , destPorts :: [String]
                      , message :: String
                      } deriving (Show)
data Alert = Alert { sid :: String
                   , connection'Alert :: Connection
                   , rule :: Rule
                   , datetime'Alert :: String
                   , origin :: String
                   , description :: String
                   } deriving (Show)
data Packet = Packet { datetime'Packet :: String
                     , connection :: Connection
                     } deriving (Show)
data Connection = Connection { protocol'Connection :: String
                             , srcIP'Connection :: String
                             , srcPort :: Maybe String
                             , destIP'Connection :: String
                             , destPort :: Maybe String
                             } deriving (Show)

-- Constant for testing
testConfig = Map.fromList $ [("$HOME_NET","10.10.10.2")
                            ,("$EXTERNAL_NET", "10.10.10.11")
                            ,("$SMTP_SERVERS","10.10.10.2")
                            ,("$HTTP_SERVERS","10.10.10.2")
                            ,("$SQL_SERVERS","10.10.10.2")
                            ,("$TELNET_SERVERS","10.10.10.2")
                            ,("$HTTP_PORTS","[80,81]")]

showPretty :: Alert -> String
showPretty alert =
    let (Alert sid (Connection protocol srcIP srcPort destIP destPort) (AlertRule _ _ _ _ _ message) datetime origin description) = alert
        portFunc = deMaybe "None" id
    in "Alert: \"" ++ message ++ "\" [" ++ sid ++ "] in packet id: " ++ sid ++ "\nDetected: " ++ datetime ++ "\nProtocol: " ++ protocol ++ "\nSource IP: " ++ srcIP ++ "\nSource port: " ++ (portFunc srcPort) ++ "\nDestination IP: " ++ destIP ++ "\nDestination port: " ++ (portFunc destPort) ++ "\nOrigin: " ++ origin ++ "\nDescription: " ++ description ++ "\n\n"

deMaybe :: y -> (x -> y) -> Maybe x -> y
deMaybe ifNothing _ Nothing = ifNothing
deMaybe _ ifSomething (Just something) = ifSomething something

descriptions :: [Alert] -> String
descriptions alerts =
    foldr (++) "" . map showPretty $ alerts
--TODO separate with newlines

main = do
  args <- getArgs
  let pcapFilename:rulesFilename:configFilename:outFilename:[] = args
  pcapContents <- readFile pcapFilename
  rulesContents <- readFile rulesFilename
  configContents <- readFile configFilename
  writeFile outFilename (doSnort rulesContents pcapContents configContents)

doSnort rulesContents pcapContents configContents =
  let configMap = (parseConfig configContents)
      rules = (parseRules rulesContents configMap)
      packets = (parsePcap pcapContents)
  in descriptions (maliciousPackets rules packets)

debugConcat contents1 contents2 contents3 =
    concat $ map (take 20) [contents1,contents2,contents3]

parseConfig configContents = testConfig --TODO
    
parseRules :: String -> Map.Map String String -> [Rule]
parseRules rulesContents configMap =
    map (parseRule configMap) (filter (/="") (lines rulesContents))

parseRule :: Map.Map String String -> String -> Rule
parseRule configMap ruleLine =
    AlertRule protocol srcIP (splitPorts srcPorts) destIP (splitPorts destPorts) message
    where ["alert", protocol, srcIP, srcPorts, "->", destIP, destPorts] = map (replaceMany configMap) . tokenizeBash . takeWhile (/='(') $ ruleLine
          extraSettings = parseExtra $ dropWhile (/='(') ruleLine
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
        datetime = line1 !! 0
        protocol = line2 !! 0
        (srcIP,srcPort) = splitOn ':' $ line1 !! 1
        (destIP,destPort) = splitOn ':' $ line1 !! 3
    in Packet datetime (Connection protocol srcIP srcPort destIP destPort)

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
    Alert sid connection rule datetime origin description
    where Packet datetime connection = packet
          sid = "LOLOLOL" --TODO
          origin = "LOLOLOL" --TODO
          description = "LOLOLOL" --TODO

isMaliciousPacket :: Packet -> Rule -> Bool
isMaliciousPacket packet rule =
    (map Char.toUpper p'protocol) == (map Char.toUpper r'protocol)
    && p'srcIP == r'srcIP
    && (p'srcPort `elem` map Just r'srcPorts || "any" `elem` r'srcPorts)
    && p'destIP == r'destIP
    && (p'destPort `elem` map Just r'destPorts || "any" `elem` r'destPorts)
    where AlertRule r'protocol r'srcIP r'srcPorts r'destIP r'destPorts message = rule
          Packet datetime (Connection p'protocol p'srcIP p'srcPort p'destIP p'destPort) = packet
    
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
    Map.fromList . map (removeNothing . (splitOn ':')) . filter (/=";") . tokenizeBash . dropWhile (=='(') $ extra
    where removeNothing = (\ (a,thing) -> case thing of
                                            Nothing -> (a,"")
                                            Just something -> (a,something))
