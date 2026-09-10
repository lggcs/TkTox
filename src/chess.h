#ifndef TT_CHESS_H
#define TT_CHESS_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

/* Self-contained chess engine for the TkTox chess interop (wire-compatible
   with toxic's game_chess.c). The board is an 8x8 grid indexed [rank][file]
   where rank 0 = rank 1 (white's back rank) and file 0 = file 'a'. Algebraic
   notation (a1-h8) is used on the wire, matching toxic. */

#define TT_CHESS_FILES 8
#define TT_CHESS_RANKS 8
#define TT_CHESS_SQUARES 64

typedef enum {
    TT_PIECE_NONE = 0,
    TT_PIECE_PAWN,
    TT_PIECE_ROOK,
    TT_PIECE_KNIGHT,
    TT_PIECE_BISHOP,
    TT_PIECE_QUEEN,
    TT_PIECE_KING,
} TTPieceType;

typedef enum {
    TT_COLOR_WHITE = 0,
    TT_COLOR_BLACK,
} TTColor;

typedef struct {
    TTPieceType type;
    TTColor color;
} TTPiece;

typedef enum {
    TT_CHESS_PLAYING = 0,
    TT_CHESS_CHECKMATE,
    TT_CHESS_STALEMATE,
    TT_CHESS_RESIGNED,
} TTChessStatus;

typedef struct {
    TTPiece board[TT_CHESS_RANKS][TT_CHESS_FILES]; /* [rank][file] */
    TTColor to_move;                              /* whose turn it is */
    bool white_ks, white_qs;                      /* castling rights */
    bool black_ks, black_qs;
    int ep_file;                                  /* en-passant target file, -1 none */
    TTChessStatus status;
    TTColor winner;                               /* valid when status != PLAYING */
} TTChess;

/* Reset to the standard starting position. */
void tt_chess_init(TTChess *g);

/* Parse an algebraic square ("a1".."h8") into rank/file. Returns false on
   malformed input. */
bool tt_chess_parse_square(const char *s, int *rank, int *file);

/* Format a rank/file into algebraic notation into out[3]. */
void tt_chess_format_square(int rank, int file, char out[3]);

/* Attempt to move the piece on (from_rank, from_file) to (to_rank, to_file)
   for the side to move. Applies castling, en passant and auto-promotion to
   queen (matching toxic, which has no promotion byte on the wire). Updates
   status (checkmate/stalemate). Returns true on success. */
bool tt_chess_move(TTChess *g, int from_rank, int from_file,
                   int to_rank, int to_file);

/* True if the side `color` is currently in check. */
bool tt_chess_in_check(const TTChess *g, TTColor color);

/* True if `color` has any legal move (used for checkmate/stalemate). */
bool tt_chess_has_legal_move(const TTChess *g, TTColor color);

/* True if the square (rank, file) is attacked by any piece of `by`. */
bool tt_chess_square_attacked(const TTChess *g, int rank, int file, TTColor by);

/* ---- wire-protocol game state (toxic game_chess.c interop) ---- */

/* A live (or pending) chess game with one friend. */
typedef struct TTChessGame {
    TTChess board;        /* engine state */
    uint32_t id;          /* game id (u32 BE on the wire) */
    TTColor self_color;   /* our colour */
    bool pending_invite;  /* we received an invite and haven't answered yet */
    bool started;         /* both sides have agreed; moves are legal */
} TTChessGame;

#endif /* TT_CHESS_H */
