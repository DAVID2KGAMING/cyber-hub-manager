package com.android.dx.command.dexer;

/** Public dx API adapter; never invokes the CLI/System.exit. */
public final class CyberCompiler {
 private CyberCompiler() {}
 public static int compile(DxContext context, String input, String output) throws java.io.IOException {
  Main.Arguments args = new Main.Arguments(context);
  args.parseFlags(new String[]{"--min-sdk-version=26", "--no-optimize", "--output="+output});
  args.fileNames = new String[]{input};
  return new Main(context).runDx(args);
 }
}
