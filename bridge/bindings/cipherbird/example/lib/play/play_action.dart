/// A button in a playground.
final class PlayAction {
  const PlayAction(this.label, this.run);

  final String label;
  final Future<void> Function() run;
}
