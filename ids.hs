import System.Environment
import System.IO
import Data.List (elemIndex)
import qualified Data.Map as Map

-- USAGE 
-- ids.exe packetfile rulesfile configfile outputfile

data Rule = AlertRule { protocol :: String
                      , srcIP :: String
                      , srcPorts :: [String]
                      , destIP :: String
                      , destPorts :: [String]
                      , message :: String
                      } deriving (Show)
data Alert = Alert { sid :: String
                   , rule :: Rule
                   , datetime :: String
                   , origin :: String
                   , description :: String
                   } deriving (Show)

showPretty :: Alert -> String
showPretty alert =
    let (Alert sid (AlertRule protocol srcIP (srcPort:_) destIP (destPort:_) message) datetime origin description) = alert
    in "Alert: \"" ++ message ++ "\" [" ++ sid ++ "] in packet id: " ++ sid ++ "\nDetected: " ++ datetime ++ "\nProtocol: " ++ protocol ++ "\nSource IP: " ++ srcIP ++ "\nSource port: " ++ srcPort ++ "\nDestination IP: " ++ destIP ++ "\nDestination port: " ++ destPort ++ "\nOrigin: " ++ origin ++ "\nDescription: " ++ description

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
  in []--descriptions (maliciousPackets rules packets)

parseConfig configContents = Map.empty --TODO
    
parseRules :: String -> Map.Map String String -> [Rule]
parseRules rulesContents configMap =
    map (parseRule configMap) (filter (/="") (lines rulesContents))

parseRule :: Map.Map String String -> String -> Rule
parseRule configMap ruleLine =
    AlertRule protocol srcIP (splitPorts srcPorts) destIP (splitPorts destPorts) message
    where ["alert", protocol, srcIP, srcPorts, "->", destIP, destPorts] = map (replaceMany configMap) . tokenizeBash . takeWhile (/='(') $ ruleLine
          extraSettings = parseExtra $ dropWhile (/='(') ruleLine
          message = "TODO" --TODO
                                                                                
splitPorts ('[':ports) =
    let noBrackets = takeWhile (/=']') ports
    in wordsWith ',' noBrackets
splitPorts port = [port]

wordsWith :: Char -> String -> [String]
wordsWith delim str =
    case splitOn delim str of
      (left,Nothing) -> [left]
      (left,Just right) -> left : (wordsWith delim right)

replaceMany :: Map.Map String String -> String -> String
replaceMany wordMap str =
    foldl helper str (Map.toList wordMap)
    where helper = (\ str (var,val) -> replaceAll var val str)

replaceAll var val "" = ""
replaceAll var val str@(s:ss)
    | startsWith var str = val ++ (drop varLen str)
    | otherwise = s : (replaceAll var val ss)
    where varLen = length var
    
startsWith [] haystack = True
startsWith needle@(n:ns) haystack@(h:hs)
    | n == h = startsWith ns hs
    | otherwise = False


parsePcap pcapContents = 
    []

maliciousPackets rules packets =
    []

tokenizeBash :: String -> [String]
tokenizeBash str = tokenizeBashHelper [] str

--acc is current word
tokenizeBashHelper :: String -> String -> [String]
tokenizeBashHelper [] [] = []
tokenizeBashHelper acc [] = [acc]
tokenizeBashHelper [] (x:xs)
    | x == '"' = tokenizeBashHelperQuoted [] xs
    | x == ' ' = (tokenizeBashHelper [] xs)
    | x == ';' = [";"] ++ (tokenizeBashHelper [] xs)
    | otherwise = tokenizeBashHelper [x] xs
tokenizeBashHelper acc (x:xs)
    | x == '"' = tokenizeBashHelperQuoted acc xs
    | x == ' ' = [acc] ++ (tokenizeBashHelper [] xs)
    | x == ';' = [acc] ++ [";"] ++ (tokenizeBashHelper [] xs)
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
      Just index -> let (left,right) = splitAt index str
                    in (left, Just right)

parseExtra :: String -> Map.Map String String
parseExtra extra =
    Map.fromList . map (removeNothing . (splitOn ':')) . filter (/=";") . tokenizeBash . dropWhile (=='(') $ extra
    where removeNothing = (\ (a,thing) -> case thing of
                                            Nothing -> (a,"")
                                            Just something -> (a,something))
