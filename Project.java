import java.io.*;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.regex.*;
import static java.nio.file.FileVisitResult.*;

public class Project {
   private static final Map<String, String> Regex = new HashMap<>();
   private static final List<Path> infectedFilesList = new ArrayList<>();
   private static int safeFile = 0;
   private static int unSafeFile = 0;
   static {
      Regex.put("Email", "[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
      Regex.put("Phone ", "[6-9]\\d{9}");
      Regex.put("Malicious Execution", "Runtime\\.getRuntime\\(\\)\\.exec\\(");
      Regex.put("JS Eval Risk", "eval\\s*\\(");
   }

   public static void main(String[] args) {
      Scanner sc = new Scanner(System.in);
      System.out.println("Secure File Inspector");
      System.out.println("Enter path:");
      String path = sc.nextLine();
      Path starPath = Paths.get(path);
      if (!Files.exists(starPath)) {
         System.out.println("path wrong enter");
         return;
      }
      System.out.printf("%-30s %-10s %-30s %-10s %-15s%n", "FileName", "Ext", "Created", "Size(byte)", "Status");
      try {
         Files.walkFileTree(starPath, new TableInspectorVisitor());
         System.out.println("\nFinal Report");
         System.out.println("Total Safe Files   : " + safeFile);
         System.out.println("Total Unsafe Files : " + unSafeFile);
         if (unSafeFile > 0) {
            manageInfectedFiles(sc);
         } else {
            System.out.println("no threats detected");
         }
      } catch (IOException e) {
         System.err.println("Error=" + e.getMessage());
      }
      sc.close();
   }

   public static class TableInspectorVisitor extends SimpleFileVisitor<Path> {
      @Override
      public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
         String folderName = dir.getFileName().toString();
         if (folderName.startsWith(".") || folderName.equals("node_modules")) {
            return SKIP_SUBTREE;
         }
         return CONTINUE;
      }

      @Override
      public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
         if (attrs.isRegularFile()) {
            String fileName = file.getFileName().toString();
            String extension = getFileExtension(fileName);
            String creationDate = attrs.creationTime().toString().split("T")[0];
            String status = checkFileStatus(file);
            if (status.equals("Safe")) {
               safeFile++;
            } else if (status.equals("Unsafe")) {
               unSafeFile++;
               infectedFilesList.add(file);
            }
            System.out.printf("%-30s %-10s %-30s %-10d %-15s%n",
                  truncate(fileName, 29), extension, creationDate, attrs.size(), status);
         }
         return CONTINUE;
      }

      private String getFileExtension(String name) {
         int lastIndex = name.lastIndexOf('.');
         return (lastIndex == -1) ? "None" : name.substring(lastIndex + 1);
      }

      private String checkFileStatus(Path filepath) {
         try {
            if (Files.size(filepath) > 5 * 1024 * 1024)
               return "Safe";
            String content = Files.readString(filepath);
            for (String patternStr : Regex.values()) {
               if (Pattern.compile(patternStr).matcher(content).find()) {
                  return "Unsafe";
               }
            }
         } catch (Exception e) {
            return "UnReadAble";
         }
         return "Safe";
      }

      private String truncate(String text, int length) {
         if (text.length() <= length)
            return text;
         return text.substring(0, length - 3);
      }
   }

   public static void manageInfectedFiles(Scanner sc) {
      System.out.println("File Management");
      System.err.println("1=export audit file");
      System.out.println("2=delete unsafe file");
      System.out.println("3=Exit");
      String choice = sc.nextLine();
      if (choice.equals("1")) {
         try (PrintWriter writer = new PrintWriter("audit_file.txt")) {
            writer.println("Scan Audit Report");
            writer.println("Date= " + new Date());
            for (Path p : infectedFilesList) {
               writer.println("unsafe" + p.toAbsolutePath());
            }
            System.out.println("report saved in audit_file.txt");
         } catch (Exception e) {
            System.out.println("Error saving report=" + e.getMessage());
         }
      } else if (choice.equals("2")) {
         System.out.print("Are you sure you want to delete" + infectedFilesList.size() + " files? (y/n): ");
         if (sc.nextLine().equalsIgnoreCase("y")) {
            for (Path p : infectedFilesList) {
               try {
                  Files.delete(p);
                  System.out.println("Deleted=" + p.getFileName());
               } catch (Exception e) {
                  System.out.println("Failed to delete=" + p.getFileName());
               }
            }
         }
      }
   }
}